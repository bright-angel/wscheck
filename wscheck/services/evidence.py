"""扫描结果证据的展示格式化：把捕获的 HTTP 报文渲染成请求/响应包。

新记录的证据结构为 {"detail": ..., "error": ..., "http": [exchange, ...]}；
旧记录没有 http 字段，调用方回退到 detail。
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from .poc.httptrace import request_path

MAX_PACKET_BODY = 6000


def exchanges(evidence) -> list[dict]:
    if not isinstance(evidence, dict):
        return []
    items = evidence.get("http")
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def packets(evidence) -> list[dict]:
    items = exchanges(evidence)
    total = len(items)
    result = []
    for index, item in enumerate(items, 1):
        method = str(item.get("method") or "").upper() or "-"
        url = str(item.get("url") or "")
        status = item.get("status") or 0
        reason = str(item.get("reason") or "")
        if not status or status >= 500:
            status_kind = "bad"
        elif status >= 400:
            status_kind = "warn"
        else:
            status_kind = "ok"
        result.append({
            "index": index,
            "total": total,
            "method": method,
            "url": url,
            "status": status,
            "status_line": f"{status} {reason}".strip() or "-",
            "status_kind": status_kind,
            "elapsed_ms": int(item.get("elapsed_ms") or 0),
            "request": _request_text(item, method, url),
            "response": _response_text(item, status, reason),
            "error": str(item.get("error") or ""),
        })
    return result


def packets_text(evidence) -> str:
    blocks = []
    for packet in packets(evidence):
        blocks.append(
            f"===== 请求 {packet['index']}/{packet['total']} =====\n{packet['request']}\n\n"
            f"===== 响应 {packet['index']}/{packet['total']} =====\n{packet['response']}"
        )
    return "\n\n".join(blocks)


def summary(evidence, limit: int = 400) -> str:
    items = exchanges(evidence)
    if items:
        parts = []
        for item in items[:4]:
            method = str(item.get("method") or "").upper() or "-"
            url = str(item.get("url") or "")
            status = item.get("status")
            mark = f"{method} {url} -> {status}" if status else f"{method} {url} -> 失败"
            parts.append(mark)
        if len(items) > 4:
            parts.append(f"其余 {len(items) - 4} 次请求略")
        text = "; ".join(parts)
    else:
        text = detail_text(evidence)
    return text if len(text) <= limit else text[:limit] + "…"


def detail_text(evidence, limit: int = 400) -> str:
    detail = evidence.get("detail") if isinstance(evidence, dict) else None
    if isinstance(detail, dict):
        text = "; ".join(f"{key}={_short(value)}" for key, value in list(detail.items())[:6])
    elif detail is None:
        text = ""
    else:
        text = _short(detail)
    return text if len(text) <= limit else text[:limit] + "…"


def detail_json(evidence) -> str:
    detail = evidence.get("detail") if isinstance(evidence, dict) else evidence
    return json.dumps(detail or {}, ensure_ascii=False, indent=2, default=str)


def error_text(evidence) -> str:
    if not isinstance(evidence, dict):
        return ""
    return str(evidence.get("error") or "")


def _request_text(item: dict, method: str, url: str) -> str:
    headers = item.get("request_headers")
    lines = [f"{method} {request_path(url)} HTTP/1.1"]
    if not isinstance(headers, dict):
        headers = {}
    # requests 在 urllib3 发送时才补 Host，PreparedRequest.headers 里通常没有
    if not any(key.lower() == "host" for key in headers):
        host = _host_of(url)
        if host:
            lines.append(f"Host: {host}")
    lines += [f"{key}: {value}" for key, value in headers.items()]
    body = str(item.get("request_body") or "")
    return "\n".join(lines) + ("\n\n" + _clip(body) if body else "")


def _response_text(item: dict, status, reason: str) -> str:
    error = str(item.get("error") or "")
    if error:
        return f"请求失败：{error}"
    headers = item.get("response_headers")
    lines = [f"HTTP/1.1 {status} {reason}".rstrip()]
    if isinstance(headers, dict):
        lines += [f"{key}: {value}" for key, value in headers.items()]
    body = str(item.get("response_body") or "")
    return "\n".join(lines) + ("\n\n" + _clip(body) if body else "")


def _clip(text: str) -> str:
    return text if len(text) <= MAX_PACKET_BODY else text[:MAX_PACKET_BODY] + "…（已截断）"


def _short(value) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text


def _host_of(url: str) -> str:
    try:
        return urlsplit(url).netloc
    except Exception:
        return ""
