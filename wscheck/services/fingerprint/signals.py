"""指纹信号采集：header / title / body / server / cert / port / favicon。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import mmh3
import requests
from cryptography import x509

from ...constants import DEFAULT_BODY_LIMIT
from .. import webfetch

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
ICON_RE = re.compile(
    r"""<link\b[^>]*rel=["']?(?:shortcut[ /]?)?icon["']?[^>]*>""", re.I
)
HREF_RE = re.compile(r"""href=["']([^"']+)["']""", re.I)
# 图标只需要算 mmh3，读满 512 KB 还没有结果的资源没有采集价值
FAVICON_LIMIT = 512 * 1024


@dataclass(slots=True)
class ProbeResult:
    url: str
    final_url: str = ""
    status_code: int | None = None
    title: str = ""
    server: str = ""
    cert: str = ""
    port: int | None = None
    favicon: str = ""
    body: str = ""
    header: str = ""
    error: str = ""

    @property
    def alive(self) -> bool:
        return self.status_code is not None

    def signals(self) -> dict[str, str]:
        return {
            "title": self.title,
            "body": self.body,
            "header": self.header,
            "server": self.server,
            "cert": self.cert,
            "port": str(self.port or ""),
            "status": str(self.status_code or ""),
            "favicon": self.favicon,
            "app": "",
            "product": "",
        }


def probe(url: str, timeout: int = 5, user_agent: str = "",
          body_limit: int = DEFAULT_BODY_LIMIT, proxies: dict | None = None) -> ProbeResult:
    """抓取单个目标；https 失败时回退 http。"""
    result = ProbeResult(url=url, port=port_of(url))
    last_error = ""
    http = webfetch.session(user_agent)
    try:
        for candidate in _candidates(url):
            try:
                response = _request(http, candidate, timeout, user_agent, proxies, body_limit)
            except (requests.RequestException, ValueError) as error:
                last_error = f"{type(error).__name__}: {error}"
                continue

            result.final_url = response.url
            result.status_code = response.status_code
            result.server = response.headers.get("Server", "")
            result.header = _render_headers(response)
            result.body = response.text or ""
            result.title = extract_title(result.body)
            result.port = port_of(response.url)
            result.favicon = _favicon_hash(http, response, user_agent, proxies)
            if response.url.startswith("https://"):
                result.cert = _format_cert(response.wscheck_cert_der)
            return result
    finally:
        http.close()

    result.error = last_error or "目标不可达"
    return result


def _candidates(url: str) -> list[str]:
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return [url, url.replace("https://", "http://", 1)]
    if parsed.scheme == "http":
        return [url, url.replace("http://", "https://", 1)]
    return [url]


def _request(http: requests.Session, url: str, timeout: int, user_agent: str,
             proxies: dict | None, body_limit: int) -> requests.Response:
    return webfetch.get(url, timeout=timeout, user_agent=user_agent, proxies=proxies,
                        limit=body_limit, http=http, capture_cert=True)


def _render_headers(response: requests.Response) -> str:
    version = getattr(response, "wscheck_http_version", 0)
    http_version = f"{version // 10}.{version % 10}" if isinstance(version, int) and version else "1.1"
    lines = [f"HTTP/{http_version} {response.status_code} {response.reason or ''}"]
    lines += [f"{key}: {value}" for key, value in response.headers.items()]
    return "\r\n".join(lines)


def extract_title(text: str) -> str:
    match = TITLE_RE.search(text)
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""


def _favicon_hash(http: requests.Session, response: requests.Response, user_agent: str,
                  proxies: dict | None = None) -> str:
    parsed = urlparse(response.url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    origin = parsed.netloc.lower()
    tags = ICON_RE.findall(response.text or "")
    hrefs = [HREF_RE.search(tag).group(1) for tag in tags if HREF_RE.search(tag)]
    # data: URI 内联图标很常见，不能当成 URL 去抓；只有 http(s) 候选才发请求
    candidates = [urljoin(f"{base}/", href.strip()) for href in hrefs]
    candidate = next((url for url in candidates if _icon_allowed(url, origin)),
                     f"{base}/favicon.ico")
    if not _icon_allowed(candidate, origin):
        return ""
    try:
        # 不跟随重定向：公共图标地址可以 302 到内网，跟随就会绕过目标的地址校验
        favicon = webfetch.get(candidate, timeout=5, user_agent=user_agent, proxies=proxies,
                               limit=FAVICON_LIMIT, accept="image/*,*/*;q=0.8", http=http,
                               allow_redirects=False)
        if favicon.status_code >= 300:
            return ""
        data = favicon.content
    except (requests.RequestException, ValueError):
        # pocsuite3 会 patch requests，畸形 URL 抛的是 ValueError 而不是 RequestException
        return ""
    return str(mmh3.hash(data)) if data else ""


def _icon_allowed(url: str, origin: str) -> bool:
    """只允许同源图标或公网图标，避免被扫描站点把采集请求引向内网。"""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return False
    if parsed.netloc.lower() == origin:
        return True
    from ..normalize import is_internal_url

    return not is_internal_url(url)


def _format_cert(der: bytes) -> str:
    if not der:
        return ""
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return ""
    return (
        f"subject={cert.subject.rfc4514_string()} "
        f"issuer={cert.issuer.rfc4514_string()} "
        f"cn={_common_name(cert.subject)}"
    )


def _common_name(subject) -> str:
    from cryptography.x509.oid import NameOID

    return ",".join(item.value for item in subject.get_attributes_for_oid(NameOID.COMMON_NAME))


def port_of(url: str) -> int | None:
    parsed = urlparse(url)
    if not parsed.scheme:
        return None
    return parsed.port or (443 if parsed.scheme == "https" else 80)
