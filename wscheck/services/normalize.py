"""输入层：原始输入 -> 规范化目标列表（去重、内网拒绝）。"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..constants import DEFAULT_PORTS
MAX_CIDR_HOSTS = 1024
_HOST_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-.]*[a-zA-Z0-9])?$")


@dataclass(slots=True)
class Target:
    url: str
    scheme: str
    host: str
    port: int
    path: str

    @property
    def key(self) -> tuple:
        return (self.scheme, self.host, self.port, self.path)


@dataclass(slots=True)
class NormalizeResult:
    targets: list[Target]
    rejected: list[tuple[str, str]]


def is_internal_url(url: str) -> bool:
    """按 URL 判断是否内网地址：单发请求（交互执行、表达式测试）也要守住同一条线。"""
    host = urlparse(url).hostname or ""
    return bool(host) and _is_internal(host)


def is_static_url(url: str, static_suffixes: tuple) -> bool:
    """按完整 URL 判断是否静态资源：POC 只该打动态入口，静态文件命中没有意义。"""
    return _is_static(urlparse(url).path or "", static_suffixes)


def normalize(raw: str, allow_internal: bool = False) -> NormalizeResult:
    targets: list[Target] = []
    seen: set[tuple] = set()
    rejected: list[tuple[str, str]] = []

    for line in _iter_lines(raw):
        candidates, error = _expand(line)
        if error:
            rejected.append((line, error))
            continue
        for candidate in candidates:
            target = _to_target(candidate)
            if target is None:
                rejected.append((line, "无法解析"))
                continue
            if not allow_internal and _is_internal(target.host):
                rejected.append((line, "内网地址（需勾选允许内网）"))
                continue
            if target.key in seen:
                continue
            seen.add(target.key)
            targets.append(target)

    return NormalizeResult(targets, rejected)


def _iter_lines(raw: str):
    for line in (raw or "").replace("\r", "\n").split("\n"):
        line = line.split("#", 1)[0].strip()
        if line:
            yield line


def _expand(line: str):
    """把一行输入展开成若干 host/url 字符串，返回 (候选列表, 错误信息)。"""
    if "/" in line and not line.lower().startswith(("http://", "https://")):
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            pass
        else:
            if network.num_addresses > MAX_CIDR_HOSTS:
                return [], f"CIDR 过大（{network.num_addresses} 个地址，上限 {MAX_CIDR_HOSTS}）"
            hosts = list(network.hosts()) or [network.network_address]
            return [str(h) for h in hosts], None

    if "://" not in line and not _looks_like_host(line.split("/", 1)[0]):
        return [], "不是合法的 URL / IP / CIDR / 域名"
    return [line], None


def _looks_like_host(value: str) -> bool:
    """裸输入允许 host、host:port 与 [IPv6]:port，端口交给 urlparse 校验。"""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    try:
        parsed = urlparse(f"//{value}")
        host = parsed.hostname
        parsed.port
    except ValueError:
        return False
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOST_RE.match(host)) and ("." in host or host == "localhost")


def _to_target(value: str) -> Target | None:
    url = value if "://" in value else _with_scheme(value)
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if not parsed.netloc or parsed.scheme not in ("http", "https"):
        return None

    scheme = parsed.scheme.lower()
    host = parsed.hostname
    if not host:
        return None
    try:
        port = parsed.port or DEFAULT_PORTS[scheme]
    except ValueError:
        return None

    path = parsed.path or "/"
    query = urlencode(sorted(parse_qsl(parsed.query)))
    display_host = f"[{host}]" if ":" in host else host
    netloc = display_host if port == DEFAULT_PORTS[scheme] else f"{display_host}:{port}"
    normalized = urlunparse((scheme, netloc, path, "", query, ""))
    return Target(url=normalized, scheme=scheme, host=host, port=port, path=path)


def _with_scheme(value: str) -> str:
    """裸输入补 https；IPv6 字面量需要加方括号才能作为 URL 主机。"""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return f"https://{value}"
    return f"https://[{value}]" if address.version == 6 else f"https://{value}"


def _is_internal(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
    )


def _is_static(path: str, suffixes: tuple) -> bool:
    return path.lower().endswith(tuple(suffixes))
