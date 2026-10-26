"""FOFA 目标导入：按查询语句调用官方 API，把结果拼成扫描目标 URL。

Key 从全局设置读取（本地 SQLite，页面不回显）；查询语句只做 base64 编码后原样提交，
不改写语法。导入的 URL 仍会经过输入层解析与内网拦截，不会因为来自 FOFA 就绕过红线。
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from urllib.parse import urlencode

import requests

from . import settings, webfetch

API_BASE = "https://fofa.info/api/v1"
FIELDS = "host,ip,port,protocol"
MAX_RESULTS = 100
MAX_QUERY = 1024
TIMEOUT = 12
RESPONSE_LIMIT = 256 * 1024


@dataclass(slots=True)
class SearchResult:
    urls: list[str]
    total: int = 0
    error: str = ""


def is_configured() -> bool:
    return bool(settings.get("fofa_key").strip())


def search(query: str, limit: int = 50, *, key: str = "",
           proxies: dict | None = None) -> SearchResult:
    """返回去重后的目标 URL；任何异常都转换成 error，不向调用方抛网络错误。"""
    query = (query or "").strip()
    if not query:
        return SearchResult([], error="FOFA 查询语句不能为空")
    if len(query) > MAX_QUERY:
        return SearchResult([], error=f"查询语句过长（上限 {MAX_QUERY} 字符）")
    key = (key or settings.get("fofa_key")).strip()
    if not key:
        return SearchResult([], error="尚未配置 FOFA API Key")

    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 50
    limit = max(1, min(limit, MAX_RESULTS))
    params = {
        "key": key,
        "qbase64": base64.b64encode(query.encode("utf-8")).decode("ascii"),
        "fields": FIELDS,
        "page": 1,
        "size": limit,
    }
    payload, error = _request(f"{API_BASE}/search/all?{urlencode(params)}", proxies)
    if error:
        return SearchResult([], error=error)
    if payload.get("error"):
        return SearchResult([], error=str(payload.get("errmsg") or "FOFA 查询失败"))

    rows = payload.get("results")
    if not isinstance(rows, list):
        return SearchResult([], error="FOFA 响应缺少 results 字段")

    urls: list[str] = []
    for row in rows:
        # fields 参数决定列顺序：host, ip, port, protocol
        if isinstance(row, str):
            values = [row]
        elif isinstance(row, (list, tuple)):
            values = list(row)
        else:
            continue
        values += [""] * (4 - len(values))
        url = _row_url(values[0], values[1], values[2], values[3])
        if url and url not in urls:
            urls.append(url)
        if len(urls) >= limit:
            break

    total = _as_int(payload.get("total"), len(urls))
    return SearchResult(urls, total=max(total, len(urls)))


def verify(key: str = "", proxies: dict | None = None) -> tuple[bool, str]:
    """用 info/my 校验 Key 是否有效，不消耗搜索额度。"""
    key = (key or settings.get("fofa_key")).strip()
    if not key:
        return False, "未配置 FOFA API Key"
    payload, error = _request(f"{API_BASE}/info/my?{urlencode({'key': key})}", proxies)
    if error:
        return False, error
    if payload.get("error"):
        return False, f"FOFA 拒绝了该 Key：{payload.get('errmsg') or '未知原因'}"

    username = str(payload.get("username") or "").strip()
    points = payload.get("fofa_point")
    detail = f"账号 {username}" if username else "Key 有效"
    if isinstance(points, (int, float)) or (isinstance(points, str) and points.isdigit()):
        detail += f"，剩余额度 {points}"
    return True, f"FOFA {detail}"


def _request(url: str, proxies: dict | None) -> tuple[dict, str]:
    proxies = settings.http_proxies() if proxies is None else proxies
    try:
        # 请求里带着 API Key，必须校验证书；扫描目标时的 verify=False 不能沿用到这里
        response = webfetch.get(url, timeout=TIMEOUT, user_agent=settings.user_agent(),
                                proxies=proxies, limit=RESPONSE_LIMIT,
                                accept=webfetch.JSON_ACCEPT, verify=True)
    except (requests.RequestException, ValueError) as error:
        return {}, f"fofa.info 请求失败：{type(error).__name__}"
    if response.status_code != 200:
        return {}, f"FOFA 返回 HTTP {response.status_code}，请检查 Key 或账号额度"
    try:
        payload = response.json()
    except ValueError:
        return {}, "FOFA 返回 200 但内容不是 JSON（请求可能被代理或网关拦截）"
    if not isinstance(payload, dict):
        return {}, "FOFA 返回格式无法识别"
    return payload, ""


def _row_url(host, ip, port, protocol) -> str:
    value = _clean(host) or _clean(ip)
    if not value:
        return ""
    if value.lower().startswith(("http://", "https://")):
        return value
    port = _clean(port)
    scheme = _clean(protocol).lower()
    if scheme not in ("http", "https"):
        scheme = "https" if port == "443" else "http"
    default_port = "443" if scheme == "https" else "80"
    if port.isdigit() and port != default_port and not _has_port(value):
        value = f"{value}:{port}"
    return f"{scheme}://{value}"


def _has_port(host: str) -> bool:
    return "]:" in host if host.startswith("[") else ":" in host


def _clean(value) -> str:
    """FOFA 返回的是外部数据：去掉空白与控制字符，异常长的主机名直接丢弃。"""
    text = str(value or "").strip()
    if len(text) > 512 or any(char.isspace() or ord(char) < 32 for char in text):
        return ""
    return text


def _as_int(value, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


__all__ = ["MAX_RESULTS", "SearchResult", "is_configured", "search", "verify"]
