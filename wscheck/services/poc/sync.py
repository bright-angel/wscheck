"""POC 仓库同步：把 GitHub 仓库中的 POC 目录镜像到本地 POC_DIR。

下载、清单、备份与回滚等通用逻辑在 services/repo_sync.py，这里只负责 POC 的配置读取与文件校验。
"""

from __future__ import annotations

from pathlib import PurePosixPath

from .. import repo_sync
from ..repo_sync import (RepositoryConfig, RepoInfo, RepoSpec, SyncError, SyncResult,
                         check_repository, extract_archive, last_sync, load_manifest,
                         normalize_ref, normalize_subdir, parse_repo_url, resolve_repo)
from . import indexer

__all__ = [
    "RepositoryConfig", "RepoInfo", "RepoSpec", "SyncError", "SyncResult",
    "check_repository", "config_from_settings", "extract_archive", "last_sync",
    "load_manifest", "normalize_ref", "normalize_subdir", "parse_repo_url",
    "resolve_repo", "sync_from_repo",
]

PY_EXCLUDED = {"__init__.py", "setup.py"}


def config_from_settings() -> RepositoryConfig:
    from .. import settings

    return RepositoryConfig(
        repo_url=settings.get("poc_repo_url"),
        ref=settings.get("poc_repo_ref"),
        subdir=settings.get("poc_repo_subdir"),
        token=settings.get("github_token"),
    )


def sync_from_repo(cfg: RepositoryConfig, poc_dir: str, state_path: str, backup_root: str,
                   proxies: dict | None = None, force: bool = False) -> SyncResult:
    """拉取仓库并镜像到 poc_dir；force=False 时提交未变化就直接复用本地文件。"""
    return repo_sync.sync_from_repo(
        cfg, poc_dir, state_path, backup_root, proxies=proxies, force=force,
        validator=_validate_poc_files, label="POC",
    )


def _validate_poc_files(files: dict[str, str]) -> None:
    py_files = [rel for rel in files
                if rel.endswith(".py") and PurePosixPath(rel).name not in PY_EXCLUDED]
    if not py_files:
        raise SyncError("仓库（子目录）里没有 POC 脚本")
    for rel in py_files:
        try:
            with open(files[rel], encoding="utf-8", errors="replace") as handle:
                sample = handle.read()
        except OSError:
            continue
        if indexer.LOADER_PATTERN.search(sample):
            return
    raise SyncError("仓库（子目录）里没有 pocsuite3 可加载的 POC（未找到 register_poc / matchers 标记）")
