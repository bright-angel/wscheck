"""pocsuite3 SDK 桥接。

pocsuite3 2.1.0 的运行期状态是进程级单例（conf / kb / cmd_line_options），
因此同一进程内多个任务的 POC 执行必须串行，用 RUN_LOCK 保证；
取消与超时只能落在批次边界（批次内由 pocsuite3 自己的线程池跑完）。

批次按"目标 × POC"两个维度切分：一次 start() 会把整批 POC 全部导入执行，
单个问题 POC（语法错误、install_requires 里写了 payload）会让整批陪葬，
所以 POC 侧默认 25 个一批，整批异常时降级为逐个执行来定位真正的肇事 POC。

pocsuite3 的 init() 会改写进程级全局（requests、socket、ssl）且执行完不还原，
本模块在导入 pocsuite3 之前记录原值，每批结束统一复原，见 _PROCESS_GLOBALS。
"""

from __future__ import annotations

import builtins
import copy
import getpass
import logging
import os
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field

import requests
import requests.api
import requests.sessions

from ...constants import DEFAULT_USER_AGENT
from ...timeutil import utcnow
from . import httptrace


def _reject_prompt(*_args, **_kwargs):
    raise RuntimeError("POC 需要交互式输入（ceye/fofa/shodan 之类平台的 token），后台执行无法提供；"
                       "请到「设置」填写 OOB 域名或 token，或在 POC 列表里停用该脚本")


# pocsuite3 的 ceye / fofa / hunter / shodan 等模块在没有配置 token 时会用
# `while True: getpass.getpass(...)` 阻塞等待终端输入。POC 跑在后台线程里没有终端，
# 一个这种 POC 就能把整批永久挂住，所以在进程内一律禁止交互式输入。
getpass.getpass = _reject_prompt
builtins.input = _reject_prompt

# pocsuite3 的 init() 会做这些进程级改写，并且执行完不还原（conf.origin_socks 只是存了个备份，没人读）：
#   requests.api.request        → 换成从 kb.session_queue 取 session（开启会话复用时）
#   requests.Session.request    → 换成 session_request：verify=False、注入公共 Cookie/代理/超时
#   socket.socket              → SOCKS 代理时整个换成 socks.socksocket
#   socket.setdefaulttimeout   → 改成上一个任务的 POC 超时
#   ssl._create_default_https_context → urllib 侧取消证书校验
# 不清回来的话，扫描之后的指纹采集、对照校验、设置自测都会跟着走代理、丢 TLS 校验，
# 关掉会话复用后普通 requests 调用还会永久卡在空的 session 队列上。必须在导入 pocsuite3 前取值。
_PROCESS_GLOBALS = {
    "api_request": requests.api.request,
    "session_request": requests.sessions.Session.request,
    "socket": socket.socket,
    "default_timeout": socket.getdefaulttimeout(),
    "https_context": ssl._create_default_https_context,
}

# pocsuite3 的运行状态写在名为 pocsuite 的 logger 上，默认只输出到 stdout，
# 任务里看不到「POC 文件加载失败 / 缺依赖 / 参数被占用」这些真正的原因
MAX_LOG_LINE = 500
# 单批最多暂存多少条引擎日志，防止调试模式下的逐目标输出把内存吃掉
MAX_COLLECTED_LOG = 400

RUN_LOCK = threading.Lock()
# pocsuite3 引擎是全局单例，排队等待超过这个时间就报错，不能无限期挂住调用线程
LOCK_WAIT_SECONDS = 120
POC_BATCH_SIZE = 25
BATCH_MIN_WALL = 90
ENGINE_BUSY_PREFIX = "POC 引擎被其他任务占用"
DEADLINE_PREFIX = "任务已达到超时上限"
MAX_EVIDENCE_CHARS = 4000
# pocsuite3 的"未命中"也是一条 fail 记录，且各 POC 文案不统一（Target is not vulnerable /
# not vulnerability / Internet noting return …），这类不算执行异常
_MISS_PATTERNS = (
    r"not\s+(?:be\s+)?vulnerable",
    r"not\s+vulnerability",
    r"(?:nothing|noting)\s+return",
    r"^(?:\w+ ){0,4}failed$",
    r"^failed to read file",
)
# 批量执行 POC 时目标主动断连/超时很常见（畸形请求会被服务栈直接 RST），降级为告警
_NETWORK_PATTERNS = (
    r"connection\s*(?:aborted|reset|refused)",
    r"remote end closed connection",
    r"(?:read\s*)?timed\s*out",
    r"broken pipe",
    r"eof occurred",
    r"\b(?:10053|10054|10060|10061)\b",
    r"ssl\s*(?:error|syscall)",
)
_MISS_RE = re.compile("|".join(_MISS_PATTERNS), re.IGNORECASE)
_NETWORK_RE = re.compile("|".join(_NETWORK_PATTERNS), re.IGNORECASE)


def is_miss(text: str) -> bool:
    return bool(_MISS_RE.search(text or ""))


def is_network_noise(text: str) -> bool:
    return bool(_NETWORK_RE.search(text or ""))


@dataclass(slots=True)
class PocOutcome:
    target: str
    poc_name: str = ""
    vul_id: str = ""
    app_name: str = ""
    status: str = "failed"
    success: bool = False
    result: dict = field(default_factory=dict)
    error: str = ""
    noise: bool = False
    duration_ms: int = 0
    created_at: object = field(default_factory=utcnow)
    exchanges: list = field(default_factory=list)

    @property
    def evidence(self) -> dict:
        # 判定依据以实际收发的报文为准，POC 自身的 result 仍保留作补充说明
        evidence = {"detail": self.result, "error": self.error}
        if self.exchanges:
            evidence["http"] = self.exchanges
        return evidence


def is_available() -> bool:
    try:
        import pocsuite3  # noqa: F401
    except Exception:
        return False
    return True


def run(targets: list[str], poc_files: list[str], threads: int = 10, timeout: int = 10,
        batch_size: int = 50, poc_batch_size: int = POC_BATCH_SIZE, deadline: float | None = None,
        user_agent: str = "", extra_options: dict | None = None, should_cancel=None, on_log=None,
        on_progress=None, debug_logs: bool = False) -> tuple[list[PocOutcome], bool, bool]:
    """按"目标 × POC"双向分批执行，返回 (结果, 是否被取消, 是否超时)。

    debug_logs 打开后引擎按 INFO 输出，每个"目标 × POC"都有一行，只在排查问题时用。
    """
    if not targets or not poc_files:
        return [], False, False

    extra = dict(extra_options or {})
    if debug_logs:
        # set_verbosity 决定 pocsuite logger 的级别，handler 收不到低于它的记录
        extra["verbose"] = 1
    size = max(1, batch_size)
    target_batches = [targets[i:i + size] for i in range(0, len(targets), size)]
    poc_size = max(1, poc_batch_size)
    poc_batches = [poc_files[i:i + poc_size] for i in range(0, len(poc_files), poc_size)]
    total = len(target_batches) * len(poc_batches)

    outcomes: list[PocOutcome] = []
    done = 0
    canceled = timed_out = False
    collector = _attach_engine_logging(logging.INFO if debug_logs else logging.WARNING)
    try:
        for t_index, t_batch in enumerate(target_batches, 1):
            for p_index, p_batch in enumerate(poc_batches, 1):
                if should_cancel and should_cancel():
                    canceled = True
                    break
                if deadline and time.monotonic() >= deadline:
                    timed_out = True
                    break
                started = time.monotonic()
                results, wedged = _run_group(t_batch, p_batch, threads, timeout, user_agent, extra,
                                             deadline, on_log)
                outcomes.extend(results)
                done += 1
                _flush_engine_log(collector, on_log)
                if on_log and (done == 1 or done % 5 == 0 or done == total or wedged):
                    on_log(f"POC 批次 {t_index}×{p_index}：{len(t_batch)} 个目标 × {len(p_batch)} 个 POC，"
                           f"用时 {time.monotonic() - started:.1f}s，进度 {done}/{total}")
                if on_progress:
                    on_progress(done, total)
                if wedged:
                    timed_out = True
                    if on_log:
                        on_log("POC 批次超时或引擎被占用，已停止后续批次", "error")
                    break
            if canceled or timed_out:
                break
    finally:
        _flush_engine_log(collector, on_log)
        _detach_engine_logging(collector)
    return outcomes, canceled, timed_out


def _run_group(targets: list[str], poc_files: list[str], threads: int, timeout: int,
               user_agent: str, extra: dict, deadline: float | None = None,
               on_log=None) -> tuple[list[PocOutcome], bool]:
    """执行一组 POC，返回 (结果, 引擎是否已不可用)；整批失败时逐个重试定位问题 POC。"""
    results, error = _run_batch(targets, poc_files, threads, timeout, user_agent, extra, deadline)
    if error is None:
        return results, False
    if _is_engine_error(error):
        return _failures(targets, "", error), True
    if len(poc_files) == 1:
        return _failures(targets, poc_files[0], error), False
    # 整批失败后逐个重试很耗时，已经到任务上限就直接交给外层收尾
    if deadline and time.monotonic() >= deadline:
        return _failures(targets, "", f"{DEADLINE_PREFIX}，剩余 POC 未执行"), False

    if on_log:
        on_log(f"POC 批次执行异常（{error}），改为逐个执行以定位问题 POC", "warning")
    merged: list[PocOutcome] = []
    for poc_file in poc_files:
        if deadline and time.monotonic() >= deadline:
            merged.extend(_failures(targets, poc_file, f"{DEADLINE_PREFIX}，未执行"))
            break
        single, single_error = _run_batch(targets, [poc_file], threads, timeout, user_agent,
                                          extra, deadline)
        if single_error is None:
            merged.extend(single)
            continue
        merged.extend(_failures(targets, poc_file, single_error))
        if _is_engine_error(single_error):
            return merged, True
    return merged, False


def _failures(targets: list[str], poc_file: str, error: str) -> list[PocOutcome]:
    name = os.path.splitext(os.path.basename(poc_file))[0] if poc_file else ""
    return [PocOutcome(target=t, poc_name=name, error=_truncate(error)) for t in targets]


def _wall_budget(poc_count: int, timeout: int) -> int:
    """单批墙钟上限：正常批次只要几秒，超过这个时间基本可以认定有 POC 不会返回。"""
    return max(BATCH_MIN_WALL, poc_count * max(1, timeout))


def _is_engine_error(error: str) -> bool:
    """引擎级故障或任务到点之后继续排队只会浪费时间，调用方应据此停止后续批次。"""
    return (error.startswith("POC 批次执行超过") or error.startswith(DEADLINE_PREFIX)
            or error.startswith(ENGINE_BUSY_PREFIX))


def _call_with_wall(func, wall: int) -> tuple[bool, object]:
    """在守护线程里执行 func 并最多等待 wall 秒。

    Python 无法强杀线程：超时后线程仍会占着 pocsuite3 的全局状态，所以这里只保证
    调用方能及时拿到结果并停止后续批次，而不是"杀掉"卡住的 POC。
    """
    box: dict[str, object] = {}

    def worker():
        try:
            box["value"] = func()
        except BaseException as error:
            box["error"] = error

    thread = threading.Thread(target=worker, daemon=True, name="wscheck-poc-batch")
    thread.start()
    thread.join(wall)
    if thread.is_alive():
        return True, None
    if "error" in box:
        raise box["error"]  # type: ignore[misc]
    return False, box.get("value")


def _run_batch(targets: list[str], poc_files: list[str], threads: int, timeout: int,
               user_agent: str, extra: dict | None = None,
               deadline: float | None = None) -> tuple[list[PocOutcome], str | None]:
    """执行一批 POC，返回 (结果, 批次级错误)；批次级错误非空表示这批一条都没跑成。"""
    wall = _wall_budget(len(poc_files), timeout)
    at_deadline = False
    if deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return [], f"{DEADLINE_PREFIX}，已停止新的 POC 批次"
        if remaining < wall:
            # 墙钟上限不能超过任务剩余时间，否则一个卡住的批次能把任务拖出几分钟
            wall = max(1, int(remaining))
            at_deadline = True
    wedged, value = _call_with_wall(
        lambda: _run_locked(targets, poc_files, threads, timeout, user_agent, extra or {}), wall)
    if wedged:
        message = (f"{DEADLINE_PREFIX}（剩余 {wall} 秒），本批 POC 已停止" if at_deadline
                   else f"POC 批次执行超过 {wall} 秒已放弃，有 POC 不会返回"
                        "（POC 引擎可能被持续占用，必要时重启服务）")
        return [], message
    return value  # type: ignore[return-value]


def _base_options(targets: list[str], poc_files: list[str], threads: int, timeout: int,
                  user_agent: str, mode: str) -> dict:
    """pocsuite3 只认 init_options 里出现过的键，所以空值一律不传，避免覆盖成空字符串。"""
    return {
        "url": list(targets),
        "poc": list(poc_files),
        "threads": int(threads),
        "timeout": int(timeout),
        "mode": mode,
        "agent": user_agent or DEFAULT_USER_AGENT,
        "quiet": True,
        "verbose": 0,
    }


def _bootstrap_engine(targets: list[str], poc_files: list[str], threads: int, timeout: int,
                      user_agent: str, mode: str, extra: dict | None):
    """导入并初始化 pocsuite3 的进程级选项，返回 (start, kb, conf)。调用方需持有 RUN_LOCK。"""
    from pocsuite3.lib.controller.controller import start
    from pocsuite3.lib.core.common import set_paths
    from pocsuite3.lib.core.data import cmd_line_options, conf, kb
    from pocsuite3.lib.core.datatype import AttribDict
    from pocsuite3.lib.core.option import init, init_options
    from pocsuite3.lib.parse.cmd import DIY_OPTIONS
    import pocsuite3

    set_paths(os.path.dirname(os.path.abspath(pocsuite3.__file__)))
    cmd_line_options.clear()
    # init_options 会把非白名单键追加进 DIY_OPTIONS（进程级列表，永不回收），
    # 上一批的 POC 参数会漏到下一批，所以每次执行前清空
    DIY_OPTIONS.clear()
    init_options(AttribDict({**_base_options(targets, poc_files, threads, timeout, user_agent, mode),
                             **(extra or {})}))
    init()
    # 在 init 之后安装，确保包装的是 pocsuite3 改写后的调用链
    httptrace.install()
    return start, kb, conf


def _run_locked(targets: list[str], poc_files: list[str], threads: int, timeout: int,
                user_agent: str, extra: dict | None = None) -> tuple[list[PocOutcome], str | None]:
    if not RUN_LOCK.acquire(timeout=LOCK_WAIT_SECONDS):
        return [], f"{ENGINE_BUSY_PREFIX}，等待 {LOCK_WAIT_SECONDS} 秒超时"
    try:
        try:
            start, kb, _conf = _bootstrap_engine(targets, poc_files, threads, timeout,
                                                 user_agent, "verify", extra)
        except Exception as error:  # pocsuite3 未安装或导入失败
            return [PocOutcome(target=t, error=f"pocsuite3 不可用: {error}") for t in targets], None

        start()
        return [_to_outcome(row) for row in list(kb.results)], None
    except SystemExit as error:
        # pocsuite3 的 register.check_requires() 在 install_requires 导入失败时直接 raise SystemExit，
        # 它是 BaseException，不会被 pocsuite3 自己的 except Exception 兜住，必须在这里拦下
        return [], f"POC 依赖检查失败（install_requires 写了非法模块名）: {error}"
    except BaseException as error:
        return [], f"POC 执行异常: {type(error).__name__}: {error}"
    finally:
        _reset_engine_state()
        RUN_LOCK.release()


def _reset_engine_state() -> None:
    """清空 pocsuite3 单例中的上一批数据，并把被改写的进程级全局恢复原状。"""
    try:
        from pocsuite3.lib.core.data import cmd_line_options, kb
        cmd_line_options.clear()
        for key in ("results", "targets", "registered_pocs"):
            collection = getattr(kb, key, None)
            if hasattr(collection, "clear"):
                collection.clear()
    except Exception:
        pass
    _restore_process_globals()


def _restore_process_globals() -> None:
    """复原 pocsuite3 在 init() 里改写的 requests / socket / ssl 全局。"""
    original = _PROCESS_GLOBALS
    if requests.api.request is not original["api_request"]:
        requests.api.request = original["api_request"]
    if requests.sessions.Session.request is not original["session_request"]:
        requests.sessions.Session.request = original["session_request"]
    if socket.socket is not original["socket"]:
        socket.socket = original["socket"]  # type: ignore[misc]
    if ssl._create_default_https_context is not original["https_context"]:
        ssl._create_default_https_context = original["https_context"]
    timeout = socket.getdefaulttimeout()
    if timeout != original["default_timeout"]:
        socket.setdefaulttimeout(original["default_timeout"])


class _EngineLogCollector(logging.Handler):
    """收集 pocsuite3 引擎日志。

    POC 加载失败、依赖缺失、必填参数没给这些原因只写在名为 pocsuite 的 logger 上，
    默认只打 stdout，任务日志里看不到。日志是在 pocsuite3 自己的工作线程里发出的，
    那些线程没有 Flask app context，不能直接落库，所以这里只收集，由批次边界统一取走。
    """

    def __init__(self) -> None:
        super().__init__()
        self._lines: list[tuple[str, str]] = []
        self._lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
        except Exception:
            return
        if not message:
            return
        level = "error" if record.levelno >= logging.ERROR else "warning"
        with self._lock:
            if len(self._lines) < MAX_COLLECTED_LOG:
                self._lines.append((message[:MAX_LOG_LINE], level))

    def drain(self) -> list[tuple[str, str]]:
        with self._lock:
            lines, self._lines = self._lines, []
        return lines


def _attach_engine_logging(level: int) -> _EngineLogCollector | None:
    try:
        from pocsuite3.lib.core.data import logger
    except Exception:
        return None
    collector = _EngineLogCollector()
    collector.setLevel(level)
    logger.addHandler(collector)
    return collector


def _detach_engine_logging(collector: _EngineLogCollector | None) -> None:
    if collector is None:
        return
    try:
        from pocsuite3.lib.core.data import logger
    except Exception:
        return
    logger.removeHandler(collector)


def _flush_engine_log(collector, on_log) -> None:
    if collector is None or on_log is None:
        return
    for message, level in collector.drain():
        on_log(f"POC 引擎：{message}", level)


INTERACTIVE_MODES = ("verify", "attack")


def execute_once(target: str, poc_file: str, mode: str = "attack",
                 options: dict | None = None, timeout: int = 15,
                 user_agent: str = "", extra_options: dict | None = None,
                 debug_logs: bool = False) -> PocOutcome:
    """单发执行一个 POC，供结果页的 attack / 命令控制台交互使用。

    POC 仍通过 pocsuite3 的受控接口运行（实例化后调用 poc.execute），不对 POC 源码做 eval；
    shell 模式要求目标回连监听端口，浏览器侧无法交互，所以交互只提供 verify/attack。
    """
    if mode not in INTERACTIVE_MODES:
        return PocOutcome(target=target, error=f"不支持的交互模式: {mode}")
    if not os.path.isfile(poc_file):
        return PocOutcome(target=target, error=f"POC 文件不存在: {poc_file}")

    extra = dict(extra_options or {})
    if debug_logs:
        extra["verbose"] = 1
    started = time.monotonic()
    wall = _wall_budget(1, timeout)
    collector = _attach_engine_logging(logging.INFO if debug_logs else logging.WARNING)
    try:
        wedged, value = _call_with_wall(
            lambda: _execute_locked(target, poc_file, mode, options or {}, timeout,
                                    user_agent, extra), wall)
        engine_lines = collector.drain() if collector else []
    finally:
        _detach_engine_logging(collector)
    outcome = (PocOutcome(target=target,
                          error=f"POC 执行超过 {wall} 秒已放弃，有 POC 不会返回"
                                "（POC 引擎可能被持续占用，必要时重启服务）")
               if wedged else value)
    outcome.duration_ms = int((time.monotonic() - started) * 1000)
    # 引擎日志来自 pocsuite3 的工作线程，那里没有应用上下文，只能在这里并回错误说明里
    if outcome.error and engine_lines:
        hints = "；".join(message for message, _ in engine_lines[:3])
        outcome.error = _truncate(f"{outcome.error}（POC 引擎：{hints}）")
    return outcome


def _execute_locked(target: str, poc_file: str, mode: str, options: dict,
                    timeout: int, user_agent: str, extra: dict) -> PocOutcome:
    """在持有引擎锁的前提下单发执行一个 POC。"""
    outcome = PocOutcome(target=target)
    if not RUN_LOCK.acquire(timeout=LOCK_WAIT_SECONDS):
        return PocOutcome(target=target,
                          error=f"{ENGINE_BUSY_PREFIX}（扫描任务），等待 {LOCK_WAIT_SECONDS} 秒超时")
    try:
        try:
            _start, kb, conf = _bootstrap_engine([target], [poc_file], 1, timeout,
                                                 user_agent, mode, extra)
        except ImportError as error:
            outcome.error = f"pocsuite3 不可用: {error}"
            return outcome
        outcome = _run_single(target, kb, conf, mode, options)
    except SystemExit as error:
        outcome.error = f"POC 依赖或必填参数检查失败: {error}"
    except BaseException as error:
        outcome.error = f"POC 执行异常: {type(error).__name__}: {error}"
    finally:
        _reset_engine_state()
        RUN_LOCK.release()
    return outcome


def _run_single(target: str, kb, conf, mode: str, options: dict) -> PocOutcome:
    registered = list(kb.registered_pocs.values())
    if not registered:
        return PocOutcome(target=target, error="POC 加载失败：文件语法错误或没有 POCBase 子类")
    poc = copy.deepcopy(registered[0])

    problems = _apply_options(poc, options)
    problems += [f"必填参数 {name} 未填写" for name, option in poc.options.items()
                 if option.require and option.value == ""]
    if problems:
        return PocOutcome(target=target, poc_name=str(getattr(poc, "name", "")),
                          error="；".join(problems))

    output = poc.execute(target, headers=getattr(conf, "http_headers", None),
                         mode=mode, verbose=False)
    success = bool(output.is_success())
    error = "" if success else _error_text(output.error_msg)
    if is_miss(error):
        error = ""
    return PocOutcome(
        target=target,
        poc_name=str(getattr(output, "name", "") or ""),
        vul_id=str(getattr(output, "vul_id", "") or ""),
        app_name=str(getattr(output, "app_name", "") or ""),
        status="success" if success else "failed",
        success=success,
        result=_plain(dict(output.result or {})),
        error=_truncate(str(error)),
        noise=is_network_noise(error),
        exchanges=_plain(getattr(output, "wscheck_exchanges", None) or []),
    )


def _apply_options(poc, options: dict) -> list[str]:
    """把用户填写的参数写进 POC 实例，返回无法接受的参数说明。"""
    problems = []
    for name, value in options.items():
        if name not in poc.options:
            problems.append(f"POC 没有参数 {name}")
            continue
        try:
            poc.set_option(name, _coerce(poc.options[name], value))
        except Exception as error:
            problems.append(f"参数 {name} 无效: {error}")
    return problems


def _coerce(option, value):
    if getattr(option, "type", "") == "Bool" and isinstance(value, str):
        return "true" if value.strip().lower() in ("1", "true", "yes", "on") else "false"
    return value


def _to_outcome(row) -> PocOutcome:
    data = dict(row)
    result = data.get("result") or {}
    status = str(data.get("status") or "failed")
    success = status == "success"
    error = "" if success else _error_text(data.get("error_msg"))
    if is_miss(error):
        error = ""
    return PocOutcome(
        target=str(data.get("target") or data.get("url") or ""),
        poc_name=str(data.get("poc_name") or data.get("name") or ""),
        vul_id=str(data.get("vul_id") or ""),
        app_name=str(data.get("app_name") or ""),
        status=status,
        success=success,
        result=_plain(result),
        error=_truncate(str(error)),
        noise=is_network_noise(error),
        exchanges=_plain(data.get("wscheck_exchanges") or []),
    )


def _error_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (tuple, list)):
        return " ".join(str(part) for part in value if part not in (None, 0, ""))
    return str(value)


def _plain(value):
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(v) for v in value]
    if isinstance(value, bytes):
        return value[:MAX_EVIDENCE_CHARS].decode("utf-8", "replace")
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _truncate(text: str) -> str:
    return text if len(text) <= MAX_EVIDENCE_CHARS else text[:MAX_EVIDENCE_CHARS] + "…（已截断）"
