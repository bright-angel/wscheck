"""非 POC 网络请求的统一入口。

统一处理 UA、代理、证书校验、连接复用，并限制读取的响应体大小：
目标返回超大页面时不能把整个响应读进内存。TLS 证书直接从已建立的响应连接上取，
不再额外建一条绕过代理的直连。
"""

from __future__ import annotations

import codecs
import ssl

import requests
import urllib3

from ..constants import DEFAULT_BODY_LIMIT, DEFAULT_USER_AGENT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# pocsuite3 的 init() 会把 requests.Session.request 换成自己的 hook（开启会话复用时连
# requests.api.request 一起换掉），执行 POC 期间不还原。那个 hook 把 timeout 强制转成 float，
# 传 (connect, read) 直接 TypeError，还会套上 POC 的代理并固定 verify=False；本项目的请求
# 不能经过它，需要在导入 pocsuite3 之前抓住原实现。
_RAW_SESSION_REQUEST = requests.sessions.Session.request

HTML_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
JSON_ACCEPT = "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"
CHUNK_SIZE = 16 * 1024


def session(user_agent: str = "") -> requests.Session:
    """一个 session 内复用连接；目录探测这类连续请求能省掉大量握手开销。"""
    http = requests.Session()
    http.verify = False
    http.headers["User-Agent"] = user_agent or DEFAULT_USER_AGENT
    return http


def request(http: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    """用未被 pocsuite3 改写的 Session.request 发请求，响应由调用方负责关闭。"""
    return _RAW_SESSION_REQUEST(http, method, url, **kwargs)


def get(url: str, *, timeout: int, user_agent: str = "", proxies: dict | None = None,
        limit: int = DEFAULT_BODY_LIMIT, accept: str = HTML_ACCEPT,
        allow_redirects: bool = True, http: requests.Session | None = None,
        capture_cert: bool = False, verify: bool = False) -> requests.Response:
    """GET 并最多读取 limit 字节；调用方可以复用传入的 session。

    扫描目标时默认不校验证书（与 pocsuite3 一致）；携带凭据访问外部 API 时应显式传 verify=True。
    """
    client = http or session(user_agent)
    owns_client = http is None
    try:
        response = request(
            client, "GET", url, timeout=timeout, verify=verify, allow_redirects=allow_redirects,
            stream=True, headers={"Accept": accept, "User-Agent": user_agent or DEFAULT_USER_AGENT},
            proxies=proxies or None,
        )
        try:
            response.wscheck_cert_der = peer_certificate(response) if capture_cert else b""
            response.wscheck_http_version = getattr(response.raw, "version", 0)
            _read_limited(response, limit)
        finally:
            # 读取中途断流也必须释放连接；已截断的响应保持未消费状态，close 会丢弃连接
            response.close()
        return response
    finally:
        if owns_client:
            client.close()


def peer_certificate(response: requests.Response) -> bytes:
    """从响应底层的 TLS socket 取服务器证书；HTTP 或连接已释放时返回空。"""
    sock = _wrapped_socket(response)
    if not isinstance(sock, ssl.SSLSocket):
        return b""
    try:
        return sock.getpeercert(binary_form=True) or b""
    except (OSError, ValueError):
        return b""


def _wrapped_socket(response: requests.Response):
    raw = getattr(response, "raw", None)
    stream = getattr(getattr(raw, "_fp", None), "fp", None)
    sock = getattr(getattr(stream, "raw", None), "_sock", None)
    if sock is None:
        sock = getattr(getattr(raw, "_connection", None), "sock", None)
    return sock


def _read_limited(response: requests.Response, limit: int) -> None:
    """读满上限就停，避免超大响应占满内存。

    提前停读时保持 `_content_consumed=False`，让 `Response.close()` 先关闭底层连接，
    否则带着未读数据的连接会被放回连接池，后续复用可能读到错位响应。
    """
    limit = max(0, int(limit))
    chunks: list[bytes] = []
    size = 0
    truncated = not limit
    if limit:
        for chunk in response.iter_content(CHUNK_SIZE):
            if not chunk:
                continue
            take = chunk[:limit - size]
            chunks.append(take)
            size += len(take)
            if size >= limit:
                # 恰好读到末尾时 iter_content 也已耗尽，无需丢弃连接
                truncated = not getattr(response.raw, "closed", False)
                break
    response._content = b"".join(chunks)
    response._content_consumed = not truncated
    response.encoding = _safe_encoding(response)


def _safe_encoding(response: requests.Response) -> str:
    """响应头里的 charset 可能是非法编码名，直接 .text 会抛 LookupError 而不是请求异常。"""
    declared = response.encoding
    if declared:
        try:
            codecs.lookup(declared)
            return declared
        except LookupError:
            pass
    return response.apparent_encoding or "utf-8"
