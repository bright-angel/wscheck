"""GitHub 仓库同步：把仓库压缩包镜像到本地目录，供 POC 与指纹规则共用。

不依赖 git 命令，直接走 GitHub REST API 下载 zipball，容器部署也能用；
私有仓库使用设置里的 GitHub Token。每次同步把文件清单写进状态 JSON，
下次只删除"上次由本工具写入、新版本已不存在"的文件，手工放进目标目录的文件不受影响；
覆盖或删除前先备份，写盘失败会尝试回滚。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
import threading
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Callable
from urllib.parse import quote, urlsplit

import requests

from . import webfetch

API_ROOT = "https://api.github.com"
GITHUB_HOSTS = {"github.com", "www.github.com"}
HTTP_USER_AGENT = "wscheck-repo-sync"
CONNECT_TIMEOUT = 10
API_READ_TIMEOUT = 30
DOWNLOAD_READ_TIMEOUT = 120
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_FILES = 20000
BACKUP_KEEP = 3

SKIP_DIRS = {".git", ".github", "__pycache__", ".pytest_cache", ".idea", ".vscode", "node_modules"}
SKIP_FILES = {".DS_Store", "Thumbs.db"}

SYNC_LOCK = threading.Lock()

OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
REF_INVALID_RE = re.compile(r"[\s\\~^:?*\[\]]")

Validator = Callable[[dict[str, str]], None]


class SyncError(Exception):
    """同步失败：消息可以直接展示给用户，不包含 Token。"""


@dataclass(frozen=True, slots=True)
class RepositoryConfig:
    repo_url: str = ""
    ref: str = ""
    subdir: str = ""
    token: str = ""


@dataclass(frozen=True, slots=True)
class RepoSpec:
    owner: str
    repo: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


@dataclass(frozen=True, slots=True)
class RepoInfo:
    spec: RepoSpec
    ref: str
    commit: str
    private: bool
    subdir: str = ""


@dataclass(slots=True)
class SyncResult:
    slug: str
    ref: str
    commit: str
    private: bool
    subdir: str = ""
    file_count: int = 0
    written: int = 0
    removed: int = 0
    unchanged: bool = False
    skipped: list[str] = field(default_factory=list)


def parse_repo_url(value: str) -> RepoSpec:
    raw = (value or "").strip()
    if not raw:
        raise SyncError("未填写仓库地址")
    if re.match(r"^[\w.-]+@[\w.-]+:", raw):
        # git@github.com:owner/repo.git
        host, _, path = raw.partition(":")
        raw = f"https://{host.split('@', 1)[1]}/{path.lstrip('/')}"
    elif "://" not in raw:
        raw = "https://" + raw
    parsed = urlsplit(raw)
    host = (parsed.hostname or "").lower()
    if parsed.scheme in ("ssh", "git") and host in GITHUB_HOSTS:
        # ssh://git@github.com/owner/repo.git 同样只用于定位仓库，实际仍走 HTTPS API
        pass
    elif parsed.scheme not in ("http", "https"):
        raise SyncError("仓库地址需要以 https://github.com/ 开头")
    else:
        if parsed.username or parsed.password:
            raise SyncError("仓库地址不要包含用户名或密码，请把 Token 填到 GitHub Token 字段")
    if host not in GITHUB_HOSTS:
        raise SyncError("目前只支持 github.com 仓库地址")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        raise SyncError("仓库地址格式应为 https://github.com/<owner>/<repo>")
    if len(parts) > 2:
        raise SyncError("请填写仓库根地址（不要带 /tree/ 等路径），分支和子目录在下方单独填写")
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not OWNER_RE.fullmatch(owner) or not REPO_RE.fullmatch(repo):
        raise SyncError("仓库地址中的 owner/repo 不合法")
    return RepoSpec(owner=owner, repo=repo)


def normalize_ref(value: str) -> str:
    ref = (value or "").strip()
    if not ref:
        return ""
    if REF_INVALID_RE.search(ref) or ".." in ref or ref.startswith("/") or ref.endswith("/"):
        raise SyncError("分支 / Tag / Commit 格式不正确")
    return ref


def normalize_subdir(value: str) -> str:
    raw = (value or "").strip().replace("\\", "/").strip("/")
    if not raw:
        return ""
    path = PurePosixPath(raw)
    if path.is_absolute() or ":" in raw or any(part in ("", ".", "..") for part in path.parts):
        raise SyncError("子目录不能是绝对路径，也不能包含 ..")
    return "/".join(path.parts)


def check_repository(cfg: RepositoryConfig, proxies: dict | None = None) -> tuple[bool, str]:
    try:
        info = resolve_repo(cfg, proxies)
    except SyncError as error:
        return False, str(error)
    kind = "私有仓库" if info.private else "公开仓库"
    subdir = f"，子目录 {info.subdir}" if info.subdir else ""
    return True, (f"仓库可访问：{info.spec.slug}（{kind}），引用 {info.ref}{subdir}，"
                  f"最新提交 {info.commit[:7]}")


def resolve_repo(cfg: RepositoryConfig, proxies: dict | None = None) -> RepoInfo:
    spec = parse_repo_url(cfg.repo_url)
    ref = normalize_ref(cfg.ref)
    subdir = normalize_subdir(cfg.subdir)
    token = (cfg.token or "").strip()
    repo = _api_get(f"{API_ROOT}/repos/{spec.slug}", token, proxies)
    ref = ref or str(repo.get("default_branch") or "main")
    commit_data = _api_get(
        f"{API_ROOT}/repos/{spec.slug}/commits/{quote(ref, safe='')}", token, proxies
    )
    commit = str(commit_data.get("sha") or "")
    if not commit:
        raise SyncError("无法解析仓库的最新提交")
    return RepoInfo(spec=spec, ref=ref, commit=commit,
                    private=bool(repo.get("private")), subdir=subdir)


def sync_from_repo(cfg: RepositoryConfig, target_dir: str, state_path: str, backup_root: str,
                   proxies: dict | None = None, force: bool = False, *,
                   validator: Validator | None = None, label: str = "POC") -> SyncResult:
    """拉取仓库并镜像到 target_dir；force=False 时提交未变化就直接复用本地文件。"""
    if not SYNC_LOCK.acquire(blocking=False):
        raise SyncError("已有一次仓库同步正在进行，请稍后再试")
    try:
        info = resolve_repo(cfg, proxies)
        token = (cfg.token or "").strip()
        source = f"{info.spec.slug}@{info.ref}#{info.subdir}"
        state = load_manifest(state_path)
        if not force and state.get("source") == source and state.get("commit") == info.commit:
            return SyncResult(slug=info.spec.slug, ref=info.ref, commit=info.commit,
                              private=info.private, subdir=info.subdir,
                              file_count=len(state.get("files") or []), unchanged=True)

        workdir = tempfile.mkdtemp(prefix="wscheck-repo-sync-")
        try:
            archive_path = os.path.join(workdir, "repo.zip")
            _download_zipball(info, token, proxies, archive_path)
            staging = os.path.join(workdir, "files")
            os.makedirs(staging, exist_ok=True)
            files = extract_archive(archive_path, staging, info.subdir, label=label)
            if validator is not None:
                validator(files)
            written, removed, skipped = _apply_snapshot(
                target_dir, files, state_path, backup_root,
                {
                    "source": source,
                    "repo": info.spec.slug,
                    "url": f"https://github.com/{info.spec.slug}",
                    "ref": info.ref,
                    "commit": info.commit,
                    "subdir": info.subdir,
                    "synced_at": _now_label(),
                },
                label=label,
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        return SyncResult(slug=info.spec.slug, ref=info.ref, commit=info.commit,
                          private=info.private, subdir=info.subdir,
                          file_count=written, written=written, removed=removed,
                          skipped=skipped)
    finally:
        SYNC_LOCK.release()


def _api_headers(token: str) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": HTTP_USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _api_get(url: str, token: str, proxies: dict | None) -> dict:
    # 走 webfetch.request：不经过 pocsuite3 在 POC 执行期间对 Session.request 的改写，
    # 否则 (connect, read) 形式的 timeout 会被它 float() 成 TypeError，请求也会被套上 verify=False
    with webfetch.session(HTTP_USER_AGENT) as http:
        try:
            response = webfetch.request(http, "GET", url, headers=_api_headers(token),
                                        proxies=proxies or None, verify=True,
                                        timeout=(CONNECT_TIMEOUT, API_READ_TIMEOUT))
        except requests.RequestException as error:
            raise SyncError(_request_error("GitHub API", error)) from error
        with response:
            if response.status_code != 200:
                raise SyncError(_status_error(response, bool(token)))
            try:
                payload = response.json()
            except ValueError as error:
                raise SyncError("GitHub API 返回的不是 JSON，可能被代理或网关拦截") from error
    if not isinstance(payload, dict):
        raise SyncError("GitHub API 返回的数据格式异常")
    return payload


def _download_zipball(info: RepoInfo, token: str, proxies: dict | None, dest: str) -> None:
    url = f"{API_ROOT}/repos/{info.spec.slug}/zipball/{info.commit}"
    with webfetch.session(HTTP_USER_AGENT) as http:
        try:
            response = webfetch.request(http, "GET", url, headers=_api_headers(token),
                                        proxies=proxies or None, verify=True, stream=True,
                                        timeout=(CONNECT_TIMEOUT, DOWNLOAD_READ_TIMEOUT))
        except requests.RequestException as error:
            raise SyncError(_request_error("下载仓库压缩包", error)) from error
        with response:
            if response.status_code != 200:
                raise SyncError(_status_error(response, bool(token)))
            expected = response.headers.get("Content-Length") or ""
            if expected.isdigit() and int(expected) > MAX_ARCHIVE_BYTES:
                raise SyncError(f"仓库压缩包超过 {MAX_ARCHIVE_BYTES // (1024 * 1024)} MB，拒绝同步")
            total = 0
            try:
                with open(dest, "wb") as handle:
                    for chunk in response.iter_content(64 * 1024):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > MAX_ARCHIVE_BYTES:
                            raise SyncError(f"仓库压缩包超过 {MAX_ARCHIVE_BYTES // (1024 * 1024)} MB，拒绝同步")
                        handle.write(chunk)
            except requests.RequestException as error:
                raise SyncError(_request_error("下载仓库压缩包", error)) from error


def _status_error(response: requests.Response, has_token: bool) -> str:
    status = response.status_code
    if status == 401:
        return "GitHub Token 无效或已过期"
    if status == 403:
        if (response.headers.get("X-RateLimit-Remaining") or "") == "0":
            return "GitHub API 访问频率超限，配置 Token 可提高限额"
        return "GitHub 拒绝访问：Token 权限不足（私有仓库需要 Contents 读取权限）"
    if status == 404:
        if has_token:
            return "仓库不存在，或当前 Token 无权访问该仓库"
        return "仓库不存在，或这是私有仓库（请配置 GitHub Token）"
    if status == 451:
        return "仓库因法律原因不可访问"
    if status >= 500:
        return f"GitHub 服务暂时不可用（HTTP {status}），稍后再试"
    return f"GitHub 返回 HTTP {status}"


def _request_error(label: str, error: Exception) -> str:
    reason = "连接超时" if isinstance(error, requests.Timeout) else "网络错误"
    return f"{label}请求失败（{reason}，{type(error).__name__}），请检查网络或代理设置"


def extract_archive(archive_path: str, staging_dir: str, subdir: str = "",
                    label: str = "POC") -> dict[str, str]:
    """解压 zipball 到 staging_dir，返回 {仓库内相对路径: 本地暂存路径}。

    只取压缩包第一层目录（GitHub 的 owner-repo-sha/）之下的内容；subdir 指定时再向下取一层。
    """
    prefix = normalize_subdir(subdir)
    prefix_parts = tuple(prefix.split("/")) if prefix else ()
    files: dict[str, str] = {}
    folded: dict[str, str] = {}
    total = 0
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for item in archive.infolist():
                if item.is_dir() or item.filename.endswith("/"):
                    continue
                if stat.S_ISLNK(item.external_attr >> 16):
                    continue
                rel = _member_rel(item.filename, prefix_parts)
                if rel is None:
                    continue
                if item.file_size > MAX_FILE_BYTES:
                    continue
                key = rel.casefold()
                if key in folded:
                    raise SyncError(f"仓库里有仅大小写不同的文件：{folded[key]} 与 {rel}，Windows 上无法同时保存")
                folded[key] = rel
                dest = os.path.join(staging_dir, *rel.split("/"))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                try:
                    with archive.open(item) as source, open(dest, "wb") as target:
                        shutil.copyfileobj(source, target)
                except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                    raise SyncError(f"解压 {rel} 失败：{error}") from error
                total += item.file_size
                if total > MAX_ARCHIVE_BYTES:
                    raise SyncError("仓库解压后体积过大，拒绝同步")
                files[rel] = dest
                if len(files) > MAX_FILES:
                    raise SyncError(f"仓库文件数超过 {MAX_FILES}，拒绝同步")
    except zipfile.BadZipFile as error:
        raise SyncError("下载的仓库压缩包损坏，请重试") from error
    if not files:
        if prefix:
            raise SyncError(f"仓库中不存在{label}子目录 {prefix}，请检查设置")
        raise SyncError("仓库压缩包里没有可同步的文件")
    return files


def _member_rel(name: str, prefix_parts: tuple[str, ...]) -> str | None:
    name = name.replace("\\", "/")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise SyncError(f"仓库压缩包包含非法路径：{name[:120]}")
    parts = PurePosixPath(name).parts
    if not parts:
        return None
    if any(part in ("", "..") for part in parts):
        raise SyncError(f"仓库压缩包包含非法路径：{name[:120]}")
    if len(parts) < 2:
        return None
    parts = parts[1:]
    if prefix_parts:
        if tuple(parts[:len(prefix_parts)]) != prefix_parts:
            return None
        parts = parts[len(prefix_parts):]
    if not parts:
        return None
    if any(part in SKIP_DIRS for part in parts[:-1]):
        return None
    if parts[-1] in SKIP_FILES or parts[-1].startswith("._"):
        return None
    return "/".join(parts)


def load_manifest(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    files = data.get("files")
    data["files"] = [str(item) for item in files] if isinstance(files, list) else []
    return data


def patch_manifest(path: str, **extra) -> None:
    """给已写入的清单补充信息（如规则 ID），读取失败时不会凭空创建清单。"""
    state = load_manifest(path)
    if not state:
        return
    state.update(extra)
    _atomic_json(path, state)


def last_sync(path: str) -> dict:
    state = load_manifest(path)
    if not state:
        return {}
    return {
        "repo": str(state.get("repo") or ""),
        "url": str(state.get("url") or ""),
        "ref": str(state.get("ref") or ""),
        "commit": str(state.get("commit") or ""),
        "subdir": str(state.get("subdir") or ""),
        "synced_at": str(state.get("synced_at") or ""),
        "file_count": len(state.get("files") or []),
    }


def _apply_snapshot(target_dir: str, files: dict[str, str], state_path: str, backup_root: str,
                    meta: dict, label: str = "POC") -> tuple[int, int, list[str]]:
    os.makedirs(target_dir, exist_ok=True)
    old_files = {rel for rel in (load_manifest(state_path).get("files") or [])}
    new_files = set(files)
    backup_dir = os.path.join(backup_root, datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    backups: list[tuple[str, str]] = []
    written: list[str] = []
    skipped: list[str] = []
    removed = 0
    try:
        for rel in sorted(old_files - new_files):
            dest = _safe_dest(target_dir, rel)
            if not os.path.isfile(dest):
                continue
            _backup(dest, rel, backup_dir, backups)
            _prune_empty(os.path.dirname(dest), target_dir)
            removed += 1
        for rel in sorted(new_files):
            source = files[rel]
            # 暂存文件可能在解压后被杀毒软件按特征隔离，先确认再动本地旧文件
            if not os.path.isfile(source):
                skipped.append(rel)
                continue
            dest = _safe_dest(target_dir, rel)
            if os.path.isdir(dest):
                raise SyncError(f"本地路径 {rel} 是目录，无法写入同名文件")
            if os.path.exists(dest):
                _backup(dest, rel, backup_dir, backups)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            temp = dest + ".wscheck-tmp"
            try:
                shutil.copy2(source, temp)
                os.replace(temp, dest)
            except OSError:
                _remove_quietly(temp)
                if not os.path.isfile(source):
                    skipped.append(rel)
                    continue
                raise
            written.append(dest)
    except (OSError, SyncError) as error:
        _rollback(written, backups)
        raise SyncError(f"写入{label}目录失败，已尝试回滚：{error}") from error

    if skipped and not written:
        _rollback(written, backups)
        raise SyncError(f"所有{label}文件在写入时都被删除，通常是本机安全软件把它们当成恶意文件隔离了；"
                        "请把目标目录加入杀毒软件信任后重试")

    payload = dict(meta)
    payload["files"] = sorted(new_files - set(skipped))
    payload["file_count"] = len(payload["files"])
    try:
        _atomic_json(state_path, payload)
    except OSError as error:
        raise SyncError(f"文件已同步，但写入同步清单失败：{error}") from error
    _prune_backups(backup_root)
    return len(payload["files"]), removed, skipped


def _safe_dest(root: str, rel: str) -> str:
    parts = PurePosixPath(rel).parts
    if not parts or any(part in ("", ".", "..") for part in parts) or PurePosixPath(rel).is_absolute():
        raise SyncError(f"同步清单里有非法路径：{rel[:120]}")
    base = os.path.abspath(root)
    dest = os.path.abspath(os.path.join(base, *parts))
    try:
        inside = os.path.commonpath([base, dest]) == base
    except ValueError:
        inside = False
    if not inside or dest == base:
        raise SyncError(f"同步清单里的路径超出目标目录：{rel[:120]}")
    return dest


def _backup(dest: str, rel: str, backup_dir: str, backups: list[tuple[str, str]]) -> None:
    target = os.path.join(backup_dir, *PurePosixPath(rel).parts)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    shutil.move(dest, target)
    backups.append((target, dest))


def _rollback(written: list[str], backups: list[tuple[str, str]]) -> None:
    for dest in reversed(written):
        _remove_quietly(dest)
    for target, dest in reversed(backups):
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.move(target, dest)
        except OSError:
            pass


def _prune_empty(start: str, root: str) -> None:
    current = os.path.abspath(start)
    base = os.path.abspath(root)
    while current != base and current.startswith(base + os.sep):
        try:
            os.rmdir(current)
        except OSError:
            break
        current = os.path.dirname(current)


def _prune_backups(root: str, keep: int = BACKUP_KEEP) -> None:
    try:
        entries = [os.path.join(root, name) for name in os.listdir(root)]
        entries = [path for path in entries if os.path.isdir(path)]
    except OSError:
        return
    entries.sort(key=lambda path: os.path.getmtime(path), reverse=True)
    for path in entries[keep:]:
        shutil.rmtree(path, ignore_errors=True)


def _atomic_json(path: str, payload: dict) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".repo-sync-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        os.replace(temp, path)
    except OSError:
        _remove_quietly(temp)
        raise


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _now_label() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
