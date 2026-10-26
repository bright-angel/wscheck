"""负向对照校验：请求同目录下随机不存在的路径，用于识别通配响应与伪 200。"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit, urlunsplit

import requests

from .. import webfetch
from ..fingerprint.signals import extract_title

VERIFY_BODY_LIMIT = 64 * 1024


def check(base_url: str, expect_status: int | None = None, expect_title: str = "",
          timeout: int = 5, user_agent: str = "", proxies: dict | None = None) -> tuple[str, str]:
    """返回 (verify_status, verify_detail)。"""
    probe_url = _random_url(base_url)
    try:
        response = webfetch.get(probe_url, timeout=timeout,
                                user_agent=user_agent or "Mozilla/5.0 (compatible; wscheck-verify)",
                                allow_redirects=False, proxies=proxies, limit=VERIFY_BODY_LIMIT)
    except (requests.RequestException, ValueError) as error:
        return "suspected", f"对照请求 {probe_url} 失败（{type(error).__name__}），需人工复核"

    status = response.status_code
    if status in (301, 302, 303, 307, 308):
        location = (response.headers.get("Location") or "").lower()
        if any(word in location for word in ("login", "signin", "index", "error")):
            return "false_positive_suspected", f"对照路径 {probe_url} 被重定向到统一页面，疑似通配响应"
        return "confirmed", f"对照路径 {probe_url} 返回 {status}，漏洞特征未复现"

    if status == 200:
        if _same_page(response.text or "", expect_title):
            return "false_positive_suspected", f"对照路径 {probe_url} 返回 200 且与首页标题一致，疑似通配/伪 200"
        return "suspected", f"对照路径 {probe_url} 意外返回 200，建议人工复核"

    if expect_status in (401, 403) and status in (401, 403):
        return "suspected", f"对照路径 {probe_url} 与目标同样被鉴权拦截，需人工复核"
    return "confirmed", f"对照路径 {probe_url} 返回 {status}，漏洞特征未复现"


def _random_url(base_url: str) -> str:
    parsed = urlsplit(base_url)
    directory, _, filename = parsed.path.rpartition("/")
    _, dot, ext = filename.rpartition(".")
    suffix = f".{ext}" if dot and 1 <= len(ext) <= 5 else ""
    path = f"{directory}/{secrets.token_hex(4)}{suffix}"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _same_page(text: str, expect_title: str) -> bool:
    if not expect_title:
        return False
    title = extract_title(text)
    return bool(title) and title.lower() == expect_title.lower()
