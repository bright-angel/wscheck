"""任务编排：状态机、后台线程执行、进度、取消与重试。"""

from __future__ import annotations

import time
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field, fields

from sqlalchemy import select, update

from ..constants import DEFAULT_BODY_LIMIT, SCAN_DEFAULTS
from ..extensions import db
from ..models import (OOB_KIND_LABELS, PocRegistry, ReviewStatus, ScanFinding, ScanTask,
                      TargetAsset, TaskLog, TaskStatus)
from ..timeutil import utcnow
from ..util import int_value
from . import normalize, settings
from .fingerprint import canonical_app, directory, engine_for
from .fingerprint.signals import probe
from .poc import runner, verify

STEP_WEIGHTS = {"normalize": 5, "fingerprint": 35, "dir_scan": 50, "poc_select": 55,
                "poc_run": 95, "finish": 100}

# 扫描模式决定"做完指纹之后还做什么"，与具体参数无关
SCAN_MODES = {
    "fingerprint": "指纹扫描",
    "full": "全指纹扫描",
    "vuln": "指纹漏洞扫描",
    "targeted": "专项扫描",
}
# 只有这两种模式做主动敏感目录探测
DIR_MODES = ("full", "vuln")


@dataclass(slots=True)
class TaskOptions:
    concurrency: int = SCAN_DEFAULTS["concurrency"]
    task_timeout: int = SCAN_DEFAULTS["task_timeout"]
    probe_timeout: int = SCAN_DEFAULTS["probe_timeout"]
    poc_timeout: int = SCAN_DEFAULTS["poc_timeout"]
    verify_timeout: int = SCAN_DEFAULTS["verify_timeout"]
    batch_size: int = SCAN_DEFAULTS["batch_size"]
    allow_internal: bool = SCAN_DEFAULTS["allow_internal"]
    skip_static: bool = SCAN_DEFAULTS["skip_static"]
    negative_verify: bool = SCAN_DEFAULTS["negative_verify"]
    scan_mode: str = "vuln"
    fingerprint_ids: list = field(default_factory=list)
    poc_ids: list = field(default_factory=list)

    @classmethod
    def from_form(cls, form, defaults: dict) -> "TaskOptions":
        def boolean(name):
            return form.get(name) in ("on", "true", "1", "1 ")

        return cls(
            concurrency=int_value(form.get("concurrency"), defaults["concurrency"], 1, 32),
            task_timeout=int_value(form.get("task_timeout"), defaults["task_timeout"], 10, 86400),
            probe_timeout=int_value(form.get("probe_timeout"), defaults["probe_timeout"], 1, 60),
            poc_timeout=int_value(form.get("poc_timeout"), defaults["poc_timeout"], 1, 120),
            verify_timeout=int_value(form.get("verify_timeout"), defaults["verify_timeout"], 1, 60),
            batch_size=int_value(form.get("batch_size"), defaults["batch_size"], 1, 200),
            allow_internal=boolean("allow_internal"),
            skip_static=boolean("skip_static"),
            negative_verify=boolean("negative_verify"),
            scan_mode=form.get("scan_mode") if form.get("scan_mode") in SCAN_MODES else "vuln",
            fingerprint_ids=_ids(form.getlist("fingerprint_ids")),
            poc_ids=_ids(form.getlist("poc_ids")),
        )


def options_from_config(config: dict | None) -> TaskOptions:
    """从任务配置还原参数；兼容旧任务里的 poc_scope（旧自动/手工筛选等价于专项扫描）。"""
    data = dict(config or {})
    if data.get("scan_mode") not in SCAN_MODES:
        data["scan_mode"] = "vuln" if data.get("poc_scope") == "all" else "targeted"
    known = {item.name for item in fields(TaskOptions)}
    defaults = asdict(TaskOptions())
    return TaskOptions(**{**defaults, **{key: value for key, value in data.items() if key in known}})


def create_task(app, name: str, raw_input: str, options: TaskOptions, auto_start: bool = True) -> ScanTask:
    task_id = str(uuid.uuid4())
    task = ScanTask(
        id=task_id,
        # 带上任务 ID 前缀，同一秒内连续建任务也不会重名
        name=name or f"任务 {task_id[:8]}",
        status=TaskStatus.PENDING,
        input_raw=raw_input,
        config_json=asdict(options),
        fingerprint_ids=options.fingerprint_ids,
        created_at=utcnow(),
    )
    db.session.add(task)
    db.session.commit()
    if auto_start:
        start(app, task.id)
    return task


def start(app, task_id: str) -> None:
    import threading

    thread = threading.Thread(target=_guarded_run, args=(_real_app(app), task_id), daemon=True,
                              name=f"wscheck-task-{task_id[:8]}")
    thread.start()


def _real_app(app):
    """视图传入的 current_app 是 LocalProxy，离开请求上下文后会失效。"""
    return app._get_current_object() if hasattr(app, "_get_current_object") else app


def _guarded_run(app, task_id: str) -> None:
    with app.app_context():
        try:
            run_pipeline(task_id)
        except Exception as error:
            app.logger.exception("任务 %s 执行失败", task_id)
            _fail(task_id, f"{type(error).__name__}: {error}")
        finally:
            db.session.remove()


def cancel(task_id: str) -> bool:
    """请求取消：排队中或运行中的任务都置为取消中，已结束的任务不受影响。"""
    task = db.session.get(ScanTask, task_id)
    if task is None:
        return False
    if task.status == TaskStatus.CANCELING:
        return True
    if task.status not in TaskStatus.ACTIVE:
        return False
    changed = db.session.execute(
        update(ScanTask)
        .where(ScanTask.id == task_id, ScanTask.status.in_((TaskStatus.PENDING, TaskStatus.RUNNING)))
        .values(status=TaskStatus.CANCELING)
    )
    db.session.commit()
    if changed.rowcount:
        log(task_id, "warning", "已请求取消，当前批次结束后停止")
        return True
    # 状态可能刚被工作线程改成终态，也可能是并发的取消请求
    db.session.expire(task)
    return task.status == TaskStatus.CANCELING


def log_many(task_id: str, entries, commit: bool = True) -> None:
    """批量写任务日志：一次事务，避免几十条忽略原因/指纹明细各提交一次。"""
    rows = [TaskLog(task_id=task_id, level=level, message=str(message)[:4000], created_at=utcnow())
            for level, message in entries]
    if rows:
        db.session.add_all(rows)
    if commit:
        db.session.commit()


def log(task_id: str, level: str, message: str) -> None:
    log_many(task_id, [(level, message)])


def recover_interrupted() -> int:
    """进程重启后，把上次未跑完的任务标记为失败，避免永久卡在 running。"""
    stale = db.session.scalars(
        select(ScanTask).where(ScanTask.status.in_(TaskStatus.ACTIVE))
    ).all()
    for task in stale:
        canceled = task.status == TaskStatus.CANCELING
        task.status = TaskStatus.CANCELED if canceled else TaskStatus.FAILED
        task.error_message = "" if canceled else "服务重启导致任务中断"
        task.finished_at = utcnow()
        db.session.add(TaskLog(task_id=task.id, level="info" if canceled else "error",
                               message="任务已取消" if canceled else "服务重启导致任务中断"))
    db.session.commit()
    return len(stale)


def run_pipeline(task_id: str) -> ScanTask:
    task = db.session.get(ScanTask, task_id)
    if task is None:
        raise ValueError(f"任务不存在: {task_id}")

    # 原子地从 PENDING 抢占为 RUNNING：若用户在建任务后立刻取消，不能再用 RUNNING 覆盖掉取消请求
    claimed = db.session.execute(
        update(ScanTask)
        .where(ScanTask.id == task_id, ScanTask.status == TaskStatus.PENDING)
        .values(status=TaskStatus.RUNNING, started_at=utcnow())
    )
    db.session.commit()
    task = db.session.get(ScanTask, task_id)
    if not claimed.rowcount:
        if task.status in (TaskStatus.CANCELING, TaskStatus.CANCELED):
            _finish(task, TaskStatus.CANCELED, message="任务在开始前已被取消")
        return task

    options = options_from_config(task.config_json)
    mode_label = SCAN_MODES.get(options.scan_mode, options.scan_mode)
    log(task.id, "info", f"任务开始：{task.name}（{mode_label}）")

    extra_options = settings.poc_options()
    user_agent = settings.user_agent()
    proxies = settings.http_proxies()
    enabled = settings.summary()
    log(task.id, "info", f"全局设置：{enabled}" if enabled else "全局设置：全部默认（直连、无 OOB）")

    targets, rejected = _normalize(task, options)
    _progress(task, "normalize")
    if not targets:
        _finish(task, TaskStatus.FAILED, error="没有可扫描的目标", message="所有输入均被拒绝或为空")
        return task

    assets, canceled = _collect_fingerprints(task, targets, options, user_agent, proxies)
    _progress(task, "fingerprint")
    if canceled:
        _finish(task, TaskStatus.CANCELED, message="任务已取消，已采集的指纹结果已保存")
        return task

    if options.scan_mode in DIR_MODES:
        canceled = _scan_directories(task, assets, options, user_agent, proxies)
        _progress(task, "dir_scan")

    if options.scan_mode in ("fingerprint", "full"):
        message = (f"{mode_label}完成，指纹与目录探测结果已保存"
                   if options.scan_mode == "full" else f"{mode_label}完成，指纹结果已保存")
        if canceled:
            _finish(task, TaskStatus.CANCELED, message="任务已取消，已完成部分的结果已保存")
        elif any(a.probe_error for a in assets):
            _finish(task, TaskStatus.PARTIAL, message=f"{mode_label}部分目标采集失败，详见日志")
        else:
            _finish(task, TaskStatus.DONE if not rejected else TaskStatus.PARTIAL, message=message)
        return task

    selected = _select_pocs(task, assets, options)
    _progress(task, "poc_select")
    runs, used = _poc_runs(task, assets, options, selected)
    if not runs:
        _finish(task, TaskStatus.DONE if not rejected else TaskStatus.PARTIAL, error="",
                message="没有匹配的 POC，指纹采集结果已保存")
        return task

    outcomes, canceled, timed_out = _run_pocs(task, runs, options, user_agent, extra_options)
    _progress(task, "poc_run")

    _save_findings(task, assets, outcomes, used, options, user_agent, proxies)
    if canceled:
        _finish(task, TaskStatus.CANCELED, message="任务已取消，已完成部分的结果已保存")
    elif timed_out:
        _finish(task, TaskStatus.PARTIAL, error=f"任务超时（{options.task_timeout} 秒），已跳过剩余 POC 批次",
                message="任务超时，已保留执行完成的 POC 结果")
    elif any(a.probe_error for a in assets) or any(o.error and not o.noise for o in outcomes):
        _finish(task, TaskStatus.PARTIAL, message="部分目标或 POC 执行失败，详见日志")
    else:
        _finish(task, TaskStatus.DONE, message="任务完成")
    return task


def _poc_targets(task: ScanTask, urls: list[str], options: TaskOptions) -> list[str]:
    """静态文件不会执行服务端逻辑，POC 打上去只会产出噪声命中，默认剔除。"""
    if not options.skip_static:
        return urls
    suffixes = _app_config("STATIC_SUFFIXES", ())
    dynamic = [url for url in urls if not normalize.is_static_url(url, suffixes)]
    skipped = len(urls) - len(dynamic)
    if skipped:
        log(task.id, "info", f"静态资源跳过 POC 检测：{skipped} 个")
    return dynamic


def _normalize(task: ScanTask, options: TaskOptions):
    result = normalize.normalize(task.input_raw, options.allow_internal)
    task.target_count = len(result.targets)
    entries = [("info", f"输入规范化：{len(result.targets)} 个目标，拒绝 {len(result.rejected)} 条")]
    entries += [("warning", f"已忽略 {line}: {reason}") for line, reason in result.rejected[:50]]
    log_many(task.id, entries)  # 与 target_count 一起提交
    return result.targets, result.rejected


def _collect_fingerprints(task: ScanTask, targets, options: TaskOptions,
                          user_agent: str, proxies: dict) -> tuple[list[TargetAsset], bool]:
    engine = engine_for(task.fingerprint_ids)
    if engine.errors:
        # 规则量大时只展示前 20 条，避免一条坏 YAML 把任务日志刷满
        entries = [("error", f"指纹规则 {rule_id} 解析失败: {error}")
                   for rule_id, error in list(engine.errors.items())[:20]]
        if len(engine.errors) > 20:
            entries.append(("error", f"其余 {len(engine.errors) - 20} 条规则解析失败已省略"))
        log_many(task.id, entries)
    timeout = options.probe_timeout
    body_limit = _app_config("BODY_LIMIT", DEFAULT_BODY_LIMIT)
    assets: list[TargetAsset] = []
    failures: list[tuple[str, str]] = []
    canceled = False

    from concurrent.futures import ThreadPoolExecutor

    pool = ThreadPoolExecutor(max_workers=min(32, max(1, options.concurrency)))
    futures = [
        pool.submit(_probe_one, engine, t, timeout, user_agent, body_limit, proxies)
        for t in targets
    ]
    try:
        for done, (target, future) in enumerate(zip(targets, futures), 1):
            if done % 10 == 1 and _cancel_requested(task.id):
                canceled = True
                break
            try:
                asset = future.result()
            except Exception as error:  # 单个目标的意外异常不能让整个任务失败
                failures.append((target.url, f"{type(error).__name__}: {error}"[:500]))
                asset = TargetAsset(url=target.url, scheme=target.scheme, host=target.host,
                                    port=target.port, probe_error=failures[-1][1],
                                    created_at=utcnow())
            asset.task_id = task.id
            db.session.add(asset)
            assets.append(asset)
            if done % 10 == 0 or done == len(futures):
                task.progress = _step_percent("normalize", "fingerprint", done, len(futures))
                db.session.commit()  # 资产与进度一起落库
    finally:
        if canceled:
            for future in futures:
                future.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
        else:
            pool.shutdown(wait=True)
    db.session.commit()

    alive = [a for a in assets if not a.probe_error]
    hits = sum(1 for a in assets if a.fingerprint)
    entries = [("info", f"指纹采集：{len(alive)} 个存活，{hits} 个命中指纹")]
    entries += [("warning", f"指纹采集异常 {url}: {error}") for url, error in failures[:20]]
    for asset in assets:
        if asset.fingerprint:
            detail = " ".join(f"{name}({score})" for name, score in asset.fingerprint.items())
            entries.append(("info", f"{asset.url} -> {detail}"))
    log_many(task.id, entries)
    return assets, canceled


def _probe_one(engine, target, timeout: int, user_agent: str, body_limit: int,
               proxies: dict) -> TargetAsset:
    result = probe(target.url, timeout=timeout, user_agent=user_agent, body_limit=body_limit,
                   proxies=proxies)
    hits, app_names = ({}, []) if result.error else engine.identify(result.signals())
    return TargetAsset(
        url=result.final_url or target.url,
        scheme=target.scheme,
        host=target.host,
        port=result.port or target.port,
        status_code=result.status_code,
        title=(result.title or "")[:512],
        server=(result.server or "")[:255],
        favicon_mmh3=result.favicon,
        app_names=app_names,
        fingerprint={engine.label(rid): int(r.score) for rid, r in hits.items()},
        probe_error=result.error,
        created_at=utcnow(),
    )


def _scan_directories(task: ScanTask, assets, options: TaskOptions, user_agent: str,
                      proxies: dict) -> bool:
    """主动敏感目录探测（全指纹 / 指纹漏洞模式），返回是否被取消。"""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    dict_path = _app_config("DIR_DICT_PATH", "")
    entries = directory.load_rules(dict_path)
    alive = [asset for asset in assets if not asset.probe_error]
    if not entries:
        log(task.id, "warning", f"主动目录探测字典为空或不可读：{dict_path}，已跳过")
        return False
    if not alive:
        return False

    timeout = options.probe_timeout
    body_limit = _app_config("BODY_LIMIT", DEFAULT_BODY_LIMIT)
    max_paths = int(_app_config("DIR_SCAN_MAX_PATHS", 0) or 0)
    total_paths = sum(len(paths) for _, paths in entries)
    log(task.id, "info", f"主动目录探测：{len(entries)} 个应用 / {total_paths} 条路径，"
                         f"{len(alive)} 个目标，单次超时 {timeout}s")
    engine = engine_for(task.fingerprint_ids)
    deadline = time.monotonic() + max(30, options.task_timeout)

    # 探测跑在线程池里，取消状态在主线程轮询后通过 Event 传进去，避免工作线程直接碰数据库会话
    from flask import current_app
    app = current_app._get_current_object()
    cancel = threading.Event()

    def watch():
        while not cancel.wait(1.0):
            with app.app_context():
                if _cancel_requested(task.id):
                    cancel.set()
                    return

    threading.Thread(target=watch, name="wscheck-dir-cancel", daemon=True).start()
    try:
        with ThreadPoolExecutor(max_workers=min(32, max(1, options.concurrency))) as pool:
            futures = [pool.submit(directory.scan_target, asset.url, entries, engine, timeout,
                                   user_agent, body_limit, proxies, max_paths,
                                   cancel.is_set, deadline) for asset in alive]
            for done, (asset, future) in enumerate(zip(alive, futures), 1):
                log_entries: list[tuple[str, str]] = []
                try:
                    result = future.result()
                except Exception as error:  # 单目标异常降级为一条告警，不影响其他目标
                    result = directory.DirResult(
                        url=asset.url, error=f"{type(error).__name__}: {error}"[:500])
                _merge_directory(asset, result, log_entries)
                task.progress = _step_percent("fingerprint", "dir_scan", done, len(futures))
                log_many(task.id, log_entries)  # 资产变更、进度与日志一次提交
    finally:
        canceled = cancel.is_set()
        cancel.set()
    hits = sum(len(asset.dir_hits or []) for asset in alive)
    log(task.id, "info", f"目录探测完成：命中 {hits} 个路径，"
                         f"{sum(1 for asset in alive if asset.dir_hits)} 个目标有发现")
    return canceled


def _merge_directory(asset: TargetAsset, result, entries: list[tuple[str, str]]) -> None:
    if result.error:
        entries.append(("warning", f"目录探测失败 {asset.url}: {result.error}"))
    known = dict(asset.fingerprint or {})
    merged = dict(known)
    for label, score in result.fingerprint.items():
        merged[label] = max(int(merged.get(label, 0)), int(score))
    if merged != known:
        asset.fingerprint = merged
    added = [f"{label}({score})" for label, score in result.fingerprint.items()
             if label not in known]
    if added:
        entries.append(("info", f"{asset.url} 报错页补充指纹：{'、'.join(added[:6])}"))
    names = list(asset.app_names or [])
    for name in result.apps:
        if name not in names:
            names.append(name)
    asset.app_names = names
    if not result.hits:
        return
    asset.dir_hits = [hit.to_dict() for hit in result.hits]
    detail = "、".join(f"{hit.app} {hit.path}" for hit in result.hits[:5])
    more = f" 等 {len(result.hits)} 个" if len(result.hits) > 5 else ""
    entries.append(("info", f"{asset.url} 目录命中：{detail}{more}"))


def _select_pocs(task: ScanTask, assets, options: TaskOptions) -> list[PocRegistry]:
    chosen, source = _pick_pocs(task, assets, options)
    task.poc_ids = [p.poc_id for p in chosen]
    log_many(task.id, [("info", f"POC 筛选：{len(chosen)} 个（{source}）")])  # 与 poc_ids 一起提交
    return [p for p in chosen if p.file_path]


def _pick_pocs(task: ScanTask, assets,
               options: TaskOptions) -> tuple[list[PocRegistry], str]:
    """按模式选 POC：手工勾选优先；否则用指纹 appName 匹配（大小写、分隔符归一）。"""
    # pocsuite3 的加载器只认正文里出现 register_poc / matchers 的脚本，其余文件不会被注册，
    # 交给引擎也只是白等一轮批次
    registry = PocRegistry.query.filter_by(enabled=1).all()
    unloadable = [p for p in registry if not p.loadable]
    if unloadable:
        names = "、".join(p.poc_id for p in unloadable[:3]) + ("…" if len(unloadable) > 3 else "")
        log(task.id, "warning", f"POC 引擎不会加载这 {len(unloadable)} 个脚本，已跳过：{names}")
    enabled = [p for p in registry if p.loadable]
    if options.poc_ids:
        wanted = set(options.poc_ids)
        chosen = [p for p in enabled if p.poc_id in wanted]
        return chosen, "手工指定"

    apps = {canonical_app(name) for asset in assets for name in (asset.app_names or [])}
    chosen = [p for p in enabled if canonical_app(p.app_name) in apps]
    chosen = _drop_heavy(task, chosen)
    if not chosen and apps:
        log(task.id, "info", "指纹已识别，但没有 POC 的 appName 与之匹配，本次不执行 POC")
    if not apps:
        log(task.id, "info", "未识别到任何指纹，专项扫描模式没有可匹配的 POC"
            if options.scan_mode == "targeted" else "未识别到任何指纹，按全量 POC 扫描")
    return chosen, "按指纹匹配"


def _poc_runs(task: ScanTask, assets, options: TaskOptions,
              matched: list[PocRegistry]) -> tuple[list[tuple[list[str], list[PocRegistry]]],
                                                    list[PocRegistry]]:
    """把目标与 POC 拆成若干次执行：指纹漏洞模式对未识别到指纹的目标回落到全量 POC。"""
    alive = [a for a in assets if not a.probe_error]
    urls = _poc_targets(task, [a.url for a in alive], options)
    apps_by_url = {a.url: (a.app_names or []) for a in alive}

    if options.scan_mode == "vuln" and not options.poc_ids:
        identified = [url for url in urls if apps_by_url.get(url)]
        unidentified = [url for url in urls if not apps_by_url.get(url)]
        runs: list[tuple[list[str], list[PocRegistry]]] = []
        if identified and matched:
            runs.append((identified, matched))
        fallback: list[PocRegistry] = []
        if unidentified:
            fallback = _drop_heavy(task, PocRegistry.query.filter(
                PocRegistry.enabled == 1, PocRegistry.loadable == 1, PocRegistry.file_path != "").all())
            if fallback:
                log(task.id, "info",
                    f"{len(unidentified)} 个目标未识别到指纹，按全量 {len(fallback)} 个 POC 扫描")
                runs.append((unidentified, fallback))
        used = _dedupe_pocs([*matched, *fallback])
        return runs, used

    used = list(matched)
    if not any(apps_by_url.get(url) for url in urls) and not options.poc_ids:
        # 专项模式：没有指纹就没有可匹配的 POC
        return [], used
    return ([(urls, matched)] if urls and matched else []), used


def _dedupe_pocs(pocs: list[PocRegistry]) -> list[PocRegistry]:
    seen: set[str] = set()
    unique = []
    for poc in pocs:
        if poc.poc_id not in seen:
            seen.add(poc.poc_id)
            unique.append(poc)
    return unique


def _run_pocs(task: ScanTask, runs: list[tuple[list[str], list[PocRegistry]]],
              options: TaskOptions, user_agent: str, extra_options: dict):
    """依次执行若干 (目标, POC) 组合，进度按各组合的工作量折算到 55%→95%。"""
    units = sum(len(urls) * len(pocs) for urls, pocs in runs)
    outcomes: list = []
    canceled = timed_out = False
    done_units = 0
    deadline = time.monotonic() + max(30, options.task_timeout)
    for urls, pocs in runs:
        if canceled or timed_out:
            break
        if not urls or not pocs:
            continue
        group_units = len(urls) * len(pocs)

        def progress(done, total, group_units=group_units, base=done_units):
            _running_progress(task, base + int(group_units * done / max(1, total)), units)

        group, canceled, timed_out = runner.run(
            urls, [p.file_path for p in pocs],
            threads=min(32, max(2, options.concurrency)),
            timeout=options.poc_timeout,
            batch_size=options.batch_size,
            user_agent=user_agent,
            extra_options=extra_options,
            deadline=deadline,
            should_cancel=lambda: _cancel_requested(task.id),
            on_log=lambda message, level="info": log(task.id, level, message),
            on_progress=progress,
            debug_logs=settings.debug_logs(),
        )
        outcomes.extend(group)
        done_units += group_units
    return outcomes, canceled, timed_out


def _drop_heavy(task: ScanTask, chosen: list[PocRegistry]) -> list[PocRegistry]:
    """默认剔除爆破 / 没有外部条件跑不完的 POC，它们能把一个目标的扫描拖到几小时。"""
    dnslog_ready = settings.oob_ready()
    allow_brute = _app_config("POC_ALLOW_HEAVY", False)
    skipped: list[str] = []
    kept: list[PocRegistry] = []
    for poc in chosen:
        if poc.bruteforce and not allow_brute:
            skipped.append(poc.heavy_reason)
            continue
        if poc.oob_kind == "search":
            skipped.append(OOB_KIND_LABELS["search"])
            continue
        if poc.needs_dnslog and not dnslog_ready:
            skipped.append("未配置 OOB")
            continue
        kept.append(poc)
    if skipped:
        detail = "、".join(f"{reason} {count} 个" for reason, count in Counter(skipped).items())
        log(task.id, "info", f"已跳过 {len(skipped)} 个 POC（{detail}），"
                             f"爆破类需要设置 WSCHECK_POC_ALLOW_HEAVY=1，OOB 类请在「设置」里配置域名或 token")
    return kept


def _save_findings(task: ScanTask, assets, outcomes, selected_pocs, options: TaskOptions,
                   user_agent: str, proxies: dict) -> None:
    by_name = {p.name: p for p in selected_pocs}
    by_id = {p.poc_id: p for p in selected_pocs}
    asset_by_host = {}
    for asset in assets:
        asset_by_host.setdefault(_host_of(asset.url), asset)

    successes = [o for o in outcomes if o.success]
    errors = [o for o in outcomes if o.error and not o.noise]
    noise = [o for o in outcomes if o.error and o.noise]
    # 全量扫描时同一类异常会重复上百次（缺依赖、需要平台 token），按 POC + 文案归组只记前 10 类
    grouped = _group_errors(errors)
    entries = [("error", line + (f"（{count} 次）" if count > 1 else ""))
               for line, count in grouped[:10]]
    if len(grouped) > 10:
        entries.append(("error", f"其余 {len(grouped) - 10} 类 POC 执行异常已省略"))
    entries += [("warning", f"POC 请求被目标中断 {outcome.target}: {outcome.error}")
                for outcome in noise[:20]]

    checks = _negative_checks(successes, asset_by_host, options, user_agent, proxies)
    for outcome, (verify_status, verify_detail) in zip(successes, checks):
        registry = by_name.get(outcome.poc_name) or by_id.get(outcome.poc_name)
        db.session.add(ScanFinding(
            task_id=task.id,
            target_url=outcome.target[:512],
            poc_id=registry.poc_id if registry else outcome.poc_name,
            poc_name=(registry.name if registry else outcome.poc_name) or "",
            severity=registry.severity if registry else "medium",
            app_name=outcome.app_name or (registry.app_name if registry else ""),
            evidence=outcome.evidence,
            verify_status=verify_status,
            verify_detail=verify_detail,
            review_status=ReviewStatus.PENDING,
            source="scan",
            created_at=utcnow(),
        ))
    entries.append(("info", f"结果写入：命中 {len(successes)} 条，执行异常 {len(errors)} 条，"
                           f"目标断连 {len(noise)} 次"))
    log_many(task.id, entries)  # 日志与命中记录一次提交


def _negative_checks(successes, asset_by_host, options: TaskOptions,
                     user_agent: str, proxies: dict) -> list[tuple[str, str]]:
    """负向对照是纯网络请求，按目标并发执行；worker 里不碰 ORM 对象。"""
    if not successes:
        return []
    if not options.negative_verify:
        return [("unverified", "")] * len(successes)

    jobs = []
    for outcome in successes:
        asset = asset_by_host.get(_host_of(outcome.target))
        jobs.append((outcome.target, asset.status_code if asset else None,
                     asset.title if asset else "", options.verify_timeout, user_agent, proxies))
    from concurrent.futures import ThreadPoolExecutor

    workers = min(8, max(1, options.concurrency), len(jobs))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_safe_verify, job) for job in jobs]
        return [future.result() for future in futures]


def _safe_verify(job) -> tuple[str, str]:
    try:
        return verify.check(*job)
    except Exception as error:  # 对照校验异常不应丢掉已经确认的扫描命中
        return "suspected", f"对照校验异常（{type(error).__name__}），需人工复核"


def _group_errors(outcomes) -> list[tuple[str, int]]:
    """同样的 POC 异常合并成一条，避免全量扫描时日志被重复信息刷满。"""
    counter: Counter = Counter()
    for outcome in outcomes:
        counter[(outcome.poc_name or "未知 POC", outcome.error)] += 1
    return [(f"POC 执行失败 {poc}: {error}", count)
            for (poc, error), count in counter.most_common()]


def _finish(task: ScanTask, status: str, error: str = "", message: str = "") -> None:
    # 取消请求来自另一个请求线程；这里重新读一次状态，避免成功终态把取消覆盖掉
    db.session.expire(task)
    if task.status in (TaskStatus.CANCELING, TaskStatus.CANCELED) and \
            status in (TaskStatus.DONE, TaskStatus.PARTIAL):
        status = TaskStatus.CANCELED
    task.status = status
    if status in (TaskStatus.DONE, TaskStatus.PARTIAL):
        task.progress = 100
    task.finished_at = utcnow()
    task.error_message = error
    if message:
        db.session.add(TaskLog(task_id=task.id, level="info" if status != TaskStatus.FAILED else "error",
                               message=message[:4000], created_at=utcnow()))
    db.session.commit()


def _fail(task_id: str, error: str) -> None:
    task = db.session.get(ScanTask, task_id)
    if task:
        _finish(task, TaskStatus.FAILED, error=error)


def _cancel_requested(task_id: str) -> bool:
    """只读检查取消标记；终态转换统一由 _finish 完成，避免多线程争写同一行。"""
    db.session.expire_all()
    task = db.session.get(ScanTask, task_id)
    return bool(task and task.status in (TaskStatus.CANCELING, TaskStatus.CANCELED))


def _progress(task: ScanTask, step: str) -> None:
    task.progress = STEP_WEIGHTS.get(step, task.progress)
    db.session.commit()


def _running_progress(task: ScanTask, done: int, total: int) -> None:
    """POC 阶段按批次推进进度条，全量扫描时避免长时间停在同一个数字。"""
    task.progress = _step_percent("poc_select", "poc_run", done, total)
    db.session.commit()


def _step_percent(start_step: str, end_step: str, done: int, total: int) -> int:
    start, end = STEP_WEIGHTS[start_step], STEP_WEIGHTS[end_step]
    return int(start + (end - start) * done / max(1, total))


def _app_config(key: str, default):
    from flask import current_app

    return current_app.config.get(key, default)


def _host_of(url: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return parsed.netloc or parsed.path


def _ids(values) -> list:
    if isinstance(values, str):
        values = [v for v in values.split(",") if v]
    return [str(v).strip() for v in values if str(v).strip()]
