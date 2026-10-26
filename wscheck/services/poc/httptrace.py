"""捕获 POC 执行期间的 HTTP 报文，作为判定依据。

POC 通常直接调用 requests（或 pocsuite3.api.requests），所以挂在
requests 的 HTTPAdapter.send 上就能拿到每一次实际发送的请求与收到的响应，
包括自动重定向的每一跳；无需改动 700+ 个 POC 源码。

不用 Session.send 是因为 requests 在 Session.send 内部就把重定向链跑完了，
它返回的是最后一跳的响应，外层那一跳会被记成最终状态码、且顺序倒置；
HTTPAdapter.send 每次只负责一跳，时间和状态码都与实际收发一致。

pocsuite3 批量执行时 POC 跑在引擎自己的线程池里，只有包住 POCBase.execute
才能把捕获结果挂回这条 target×poc 的 Output。仅在判定成功时保留报文：
kb.results 会保存所有目标的执行记录，未命中的报文对结果页没有价值。
"""

from __future__ import annotations

import threading
import time
from urllib.parse import urlsplit

import requests.adapters

MAX_EXCHANGES = 12
MAX_URL = 1500
MAX_REQUEST_BODY = 2000
MAX_RESPONSE_BODY = 6000
MAX_HEADER_ITEMS = 40
MAX_HEADER_CHARS = 400

_local = threading.local()
_install_lock = threading.Lock()
_installed = False
_base_send = requests.adapters.HTTPAdapter.send
_base_execute = None


def install() -> None:
    """安装请求捕获钩子；pocsuite3 init 之后调用，可重复调用。"""
    global _installed, _base_send, _base_execute
    with _install_lock:
        if _installed:
            return
        from pocsuite3.lib.core.poc import POCBase

        _base_send = requests.adapters.HTTPAdapter.send
        requests.adapters.HTTPAdapter.send = _adapter_send_with_capture
        _base_execute = POCBase.execute
        POCBase.execute = _execute_with_capture
        _installed = True


def _begin() -> list | None:
    previous = getattr(_local, "exchanges", None)
    _local.exchanges = []
    return previous


def _end(previous: list | None) -> list:
    collected = getattr(_local, "exchanges", None) or []
    if previous is None:
        try:
            del _local.exchanges
        except AttributeError:
            pass
    else:
        _local.exchanges = previous
    return collected


def _execute_with_capture(self, *args, **kwargs):
    previous = _begin()
    try:
        output = _base_execute(self, *args, **kwargs)
    finally:
        exchanges = _end(previous)
    if output is not None and exchanges:
        try:
            if output.is_success():
                output.wscheck_exchanges = exchanges
        except Exception:
            pass
    return output


def _adapter_send_with_capture(self, request, *args, **kwargs):
    bucket = getattr(_local, "exchanges", None)
    if bucket is None or len(bucket) >= MAX_EXCHANGES:
        return _base_send(self, request, *args, **kwargs)

    record = {
        "method": str(request.method or "").upper()[:16],
        "url": str(request.url or "")[:MAX_URL],
        "request_headers": _headers(getattr(request, "headers", None)),
        "request_body": _request_body(getattr(request, "body", None)),
        "status": 0,
        "reason": "",
        "response_headers": {},
        "response_body": "",
        "elapsed_ms": 0,
        "error": "",
    }
    started = time.monotonic()
    try:
        response = _base_send(self, request, *args, **kwargs)
    except BaseException as error:
        record["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        record["error"] = f"{type(error).__name__}: {error}"[:MAX_HEADER_CHARS]
        bucket.append(record)
        raise

    record["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    record["status"] = int(getattr(response, "status_code", 0) or 0)
    record["reason"] = str(getattr(response, "reason", "") or "")[:200]
    record["response_headers"] = _headers(getattr(response, "headers", None))
    # stream=True 时读取 content 会把流提前消费掉，改变 POC 自身的行为
    if not _is_streaming(args, kwargs):
        record["response_body"] = _response_body(response)
    bucket.append(record)
    return response


def _is_streaming(args, kwargs) -> bool:
    if "stream" in kwargs:
        return bool(kwargs["stream"])
    # HTTPAdapter.send(self, request, stream=False, ...)
    return bool(args[0]) if args else False


def _headers(headers) -> dict:
    if not headers:
        return {}
    try:
        items = list(headers.items())
    except Exception:
        return {}
    result = {}
    for name, value in items[:MAX_HEADER_ITEMS]:
        result[str(name)[:100]] = str(value)[:MAX_HEADER_CHARS]
    return result


def _request_body(body) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        return body[:MAX_REQUEST_BODY].decode("utf-8", "replace")
    if isinstance(body, str):
        return body[:MAX_REQUEST_BODY]
    return f"<{type(body).__name__} 数据流，未捕获>"


def _response_body(response) -> str:
    try:
        content = response.content or b""
    except Exception as error:
        return f"<读取响应失败: {type(error).__name__}: {error}>"[:MAX_HEADER_CHARS]
    if not content:
        return ""
    # 先按上限截断字节再解码，避免大响应体整段解码
    truncated = content[: MAX_RESPONSE_BODY * 4]
    try:
        text = truncated.decode(getattr(response, "encoding", None) or "utf-8", "replace")
    except LookupError:
        text = truncated.decode("utf-8", "replace")
    if len(text) > MAX_RESPONSE_BODY:
        text = text[:MAX_RESPONSE_BODY] + "…（已截断）"
    return text


def request_path(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except Exception:
        return url
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return path
