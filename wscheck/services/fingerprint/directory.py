"""主动敏感目录探测：按字典路径请求目标，再用指纹引擎判断响应属于哪个应用。

字典是"应用名 -> 路径列表"（如 Alibaba-Nacos -> /nacos/），与本项目的指纹 app_name 同一套命名，
命中后可直接参与"指纹对应 POC"的筛选。为避免把反向代理的伪 200 当成命中，每个目标先请求一个
随机不存在路径作为软 404 基线：状态码相同且正文（忽略路径回显与空白）一致时视为未命中。
有些站点按后缀通配（任意 .html 都回首页），所以基线按请求路径的后缀分别缓存，根路径则对照首页;
命中与字典应用相关的指纹时不看基线——那本身就是强证据。基线与 404/500 报错页也会单独跑一遍
指纹识别（正文窗口更大），框架的调试页常把产品名放在页面后半段，靠普通页面采集不到。
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
import yaml

from ...constants import DEFAULT_BODY_LIMIT
from .. import webfetch
from . import related_app
from .engine import FingerprintEngine
from .signals import extract_title, port_of

BASELINE_PATH = "/.wscheck-not-found-3f7a1c"
MAX_BODY = 4096
# 报错页常在页面后半段放框架信息（ThinkPHP 的调试页 "ThinkPHP" 字样就在 6 KB 之后），
# 基线/错误响应需要更大的正文窗口才能识别出应用指纹
ERROR_BODY = 32768
# 返回这些状态码说明路径存在但需要认证/被禁止，即使与基线一致也算有效发现
REAL_STATUS = (200, 401, 403)
# 单个目标在目录探测上的墙钟上限（按单次超时倍数估算），避免全超时的目标吃掉整个任务
WALL_FACTOR = 8
MIN_WALL = 30


@dataclass(slots=True)
class DirHit:
    app: str
    path: str
    status: int
    title: str = ""
    matched: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"app": self.app, "path": self.path, "status": self.status,
                "title": self.title, "matched": list(self.matched)}


@dataclass(slots=True)
class DirResult:
    url: str
    requests: int = 0
    hits: list[DirHit] = field(default_factory=list)
    apps: list[str] = field(default_factory=list)
    # 从报错页 / 软 404 基线里识别出的指纹（不依赖路径是否存在）
    fingerprint: dict[str, int] = field(default_factory=dict)
    error: str = ""


_CACHE: dict[str, object] = {"path": "", "mtime": 0.0, "entries": []}


def load_rules(path: str) -> list[tuple[str, list[str]]]:
    """读取字典，按 mtime 缓存；文件缺失或格式不对时返回空列表（任务里会记一条告警）。"""
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return []
    if _CACHE["path"] == path and _CACHE["mtime"] == mtime:
        return _CACHE["entries"]  # type: ignore[return-value]
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError):
        return []
    entries: list[tuple[str, list[str]]] = []
    if isinstance(data, dict):
        for app, paths in data.items():
            if not isinstance(app, str) or not isinstance(paths, list):
                continue
            clean = [item.strip() for item in paths
                     if isinstance(item, str) and item.strip().startswith("/")]
            if clean:
                entries.append((app.strip(), clean))
    _CACHE.update(path=path, mtime=mtime, entries=entries)
    return entries


def scan_target(url: str, entries: list[tuple[str, list[str]]], engine: FingerprintEngine,
                timeout: int = 5, user_agent: str = "",
                body_limit: int = DEFAULT_BODY_LIMIT,
                proxies: dict | None = None, max_paths: int = 0,
                should_cancel=None, deadline: float | None = None) -> DirResult:
    """探测一个目标。每个应用命中第一个有效路径后即停止，返回命中的路径与识别出的应用名。"""
    http = webfetch.session(user_agent)
    try:
        return _scan_target(url, entries, engine, http, timeout, user_agent, body_limit,
                            proxies, max_paths, should_cancel, deadline)
    finally:
        http.close()


def _scan_target(url: str, entries: list[tuple[str, list[str]]], engine: FingerprintEngine,
                 http: requests.Session, timeout: int, user_agent: str, body_limit: int,
                 proxies: dict | None, max_paths: int,
                 should_cancel, deadline: float | None) -> DirResult:
    result = DirResult(url=url)
    origin = _origin(url)
    if not origin:
        result.error = "无法解析目标地址"
        return result
    wall = time.monotonic() + max(MIN_WALL, timeout * WALL_FACTOR)
    if deadline:
        wall = min(wall, deadline)

    baselines: dict[str, requests.Response | None] = {}
    home: list[requests.Response | None] = []

    def fetch(path: str) -> requests.Response | None:
        result.requests += 1
        return _fetch(http, origin + path, timeout, user_agent, proxies, body_limit)

    def baseline_for(path: str) -> requests.Response | None:
        if urlparse(path).path in ("", "/"):
            if not home:
                home.append(fetch("/"))
                _remember_response(result, engine, home[0], origin)
            return home[0]
        suffix = _suffix(path)
        if suffix not in baselines:
            baselines[suffix] = fetch(BASELINE_PATH + suffix)
            _remember_response(result, engine, baselines[suffix], origin)
        return baselines[suffix]

    for app, paths in entries:
        for path in paths:
            if max_paths and result.requests >= max_paths:
                return result
            if time.monotonic() >= wall or (should_cancel and should_cancel()):
                return result
            response = fetch(path)
            if response is None:
                continue
            soft = _is_soft_404(response, baseline_for(path), path)
            # 404 / 500 / 软 404 页面也可能带着框架指纹（如 ThinkPHP 的系统错误页），
            # 即使路径不存在也要把这些指纹收下，供后面的 POC 筛选使用
            error_page = soft or response.status_code >= 400
            hits, app_names = engine.identify(
                _signals(response, origin, ERROR_BODY if error_page else MAX_BODY))
            if error_page:
                _remember_hits(result, engine, hits, app_names)
            if soft or response.status_code not in REAL_STATUS:
                continue
            # 只认与字典应用对应的指纹：目标所有页面都可能命中 "PHP"、"nginx" 这类通用规则，
            # 那不能说明这个路径存在
            related = [name for name in app_names if related_app(app, name)]
            labels = [engine.label(rid) for rid in hits
                      if related_app(app, engine.label(rid))]
            result.hits.append(DirHit(app=app, path=path, status=response.status_code,
                                      title=extract_title(response.text or "")[:200],
                                      matched=labels))
            _add_unique(result.apps, app)
            for name in related:
                _add_unique(result.apps, name)
            break
    return result


def _remember_response(result: DirResult, engine: FingerprintEngine,
                       response: requests.Response | None, origin: str) -> None:
    if response is None:
        return
    hits, app_names = engine.identify(_signals(response, origin, ERROR_BODY))
    _remember_hits(result, engine, hits, app_names)


def _remember_hits(result: DirResult, engine: FingerprintEngine, hits, app_names) -> None:
    """记录报错页识别出的应用：不要求路径存在，只用于补全目标指纹。"""
    for rule_id, evaluation in hits.items():
        label = engine.label(rule_id)
        score = int(evaluation.score)
        if score > result.fingerprint.get(label, 0):
            result.fingerprint[label] = score
    for name in app_names:
        _add_unique(result.apps, name)


def _fetch(http: requests.Session, url: str, timeout: int, user_agent: str,
           proxies: dict | None, body_limit: int) -> requests.Response | None:
    try:
        # 报错页/基线要用更大的正文窗口识别框架，这里统一按两者上限读取，避免整页进内存
        return webfetch.get(url, timeout=timeout, user_agent=user_agent, proxies=proxies,
                            limit=max(body_limit, ERROR_BODY), accept=webfetch.JSON_ACCEPT,
                            http=http)
    except (requests.RequestException, ValueError):
        return None


def _signals(response: requests.Response, origin: str,
             body_limit: int = MAX_BODY) -> dict[str, str]:
    """只取目录探测关心的信号：favicon 与证书要额外发请求/建连接，这里不采集。"""
    text = response.text or ""
    headers = "\r\n".join(f"{key}: {value}" for key, value in response.headers.items())
    return {
        "title": extract_title(text),
        "body": text[:body_limit],
        "header": headers,
        "server": response.headers.get("Server", ""),
        "status": str(response.status_code),
        "port": str(port_of(response.url or origin) or ""),
        "cert": "",
        "favicon": "",
        "app": "",
        "product": "",
    }


def _is_soft_404(response: requests.Response, baseline: requests.Response | None,
                 path: str) -> bool:
    """反向代理/SPA 常对任意路径返回同一页，用基线响应把这类"伪命中"排除。

    401/403 也要按正文比对：整站统一鉴权时任意路径都回同一页 401，属于伪命中；
    而受保护资源会返回自己的登录/拒绝页，正文与基线不同，应当算有效发现。
    """
    if baseline is None:
        return False
    if response.status_code != baseline.status_code:
        return False
    body = (response.text or "")[:MAX_BODY]
    stripped = path.rstrip("/")
    if stripped and len(stripped) > 2 and stripped in body:
        # 把请求路径原样回显的 404 页面
        return True
    return _signature(body, path) == _signature(baseline.text or "", BASELINE_PATH)


def _signature(text: str, drop_path: str) -> str:
    normalized = text[:MAX_BODY].replace(drop_path, "{path}")
    return hashlib.sha1(re.sub(r"\s+", " ", normalized).encode("utf-8", "ignore")).hexdigest()


def _suffix(path: str) -> str:
    suffix = os.path.splitext(urlparse(path).path)[1].lower()
    return suffix if len(suffix) <= 10 else ""


def _origin(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _add_unique(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


__all__ = ["DirHit", "DirResult", "load_rules", "scan_target"]
