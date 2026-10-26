"""结果行上的交互式 POC 执行：attack 模式与命令控制台。

只调用 runner.execute_once（pocsuite3 受控接口），每次执行都写入 poc_actions 留痕。
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from ..extensions import db
from ..models import PocAction, PocRegistry, ScanFinding, TaskLog
from ..services import evidence, normalize, settings
from ..services.poc import runner
from ..timeutil import fmt_dt, session_tz, utcnow
from .common import get_or_404

bp = Blueprint("actions", __name__, url_prefix="/findings")

MODES = ("attack", "command")


@bp.get("/<int:finding_id>/panel")
def panel(finding_id):
    finding = get_or_404(ScanFinding, finding_id, "结果")
    registry = db.session.get(PocRegistry, finding.poc_id)
    actions = (PocAction.query.filter_by(finding_id=finding.id)
               .order_by(PocAction.id.desc()).limit(30).all())
    return jsonify({
        "finding_id": finding.id,
        "target_url": finding.target_url,
        "poc": _poc_payload(registry),
        "actions": [_action_payload(action) for action in actions],
    })


@bp.post("/<int:finding_id>/execute")
def execute(finding_id):
    finding = get_or_404(ScanFinding, finding_id, "结果")
    payload = request.get_json(silent=True) or {}
    mode = payload.get("mode")
    registry = db.session.get(PocRegistry, finding.poc_id)
    if mode not in MODES:
        return _bad_request(f"未知的执行模式: {mode}")
    if registry is None or not registry.file_path:
        return _bad_request("该结果没有对应的 POC 脚本，无法交互执行")
    if not registry.loadable:
        # 引擎的加载器会直接跳过这类文件，跑一次也只是占着 POC 锁拿不到任何输出
        return _bad_request(f"pocsuite3 不会加载这个脚本：{registry.load_error or '缺少 register_poc 调用'}")
    if not registry.supports_attack:
        return _bad_request("该 POC 未实现 attack 模式，无法交互执行")
    if normalize.is_internal_url(finding.target_url) and not _allows_internal(finding):
        return _bad_request("目标是内网地址，交互执行沿用扫描口径：需要先在所属任务里勾选「允许内网」")

    try:
        options = _requested_options(registry, mode, payload.get("options") or {})
    except ValueError as error:
        return _bad_request(str(error))

    timeout = max(15, int(current_app.config["SCAN_DEFAULTS"]["poc_timeout"]))
    outcome = runner.execute_once(finding.target_url, registry.file_path,
                                  "attack" if mode == "command" else mode,
                                  {**settings.parse_poc_defaults(), **options}, timeout,
                                  user_agent=settings.user_agent(),
                                  extra_options=settings.poc_options(),
                                  debug_logs=settings.debug_logs())
    action = _record(finding, registry, mode, options, outcome)
    db.session.add(TaskLog(task_id=finding.task_id, level="info" if outcome.success else "warning",
                           message=f"交互执行 {mode}：{finding.poc_id} → {finding.target_url}"
                                   f"（{'成功' if outcome.success else '未成功'}）",
                           created_at=utcnow()))
    db.session.commit()
    return jsonify({"action": _action_payload(action)})


def _requested_options(registry: PocRegistry, mode: str, supplied: dict) -> dict:
    """命令控制台把输入的命令映射到 POC 自己的命令参数上。"""
    if mode != "command":
        return {str(k): str(v) for k, v in supplied.items() if isinstance(v, (str, int, float))}
    option = registry.command_option
    if not option:
        raise ValueError("该 POC 没有可注入命令的参数，无法使用命令控制台")
    command = str(supplied.get("command") or "").strip()
    if not command:
        raise ValueError("请输入要执行的命令")
    return {option: command}


def _bad_request(message: str):
    return jsonify({"error": message}), 400


def _record(finding: ScanFinding, registry: PocRegistry, mode: str, options: dict,
            outcome) -> PocAction:
    action = PocAction(
        task_id=finding.task_id,
        finding_id=finding.id,
        poc_id=registry.poc_id,
        target_url=finding.target_url,
        mode=mode,
        options=options,
        status="success" if outcome.success else "failed",
        output=outcome.result,
        exchanges=list(outcome.exchanges or []),
        error=outcome.error,
        duration_ms=outcome.duration_ms,
        created_at=utcnow(),
    )
    db.session.add(action)
    db.session.flush()
    return action


def _poc_payload(registry: PocRegistry | None) -> dict:
    if registry is None:
        return {"exists": False, "attack": False, "console": False, "shell_only": False,
                "command_option": "", "options": []}
    return {
        "exists": True,
        "poc_id": registry.poc_id,
        "name": registry.name,
        **registry.capabilities,
        "loadable": bool(registry.loadable),
        "load_error": registry.load_error,
        "command_option": registry.command_option,
        "options": registry.poc_options or [],
    }


def _action_payload(action: PocAction) -> dict:
    return {
        "id": action.id,
        "mode": action.mode,
        "options": action.options or {},
        "status": action.status,
        "output": action.output or {},
        # POC 的 result 可能被脚本自身截断（例如只保留响应前 4000 字符），
        # 报文里是实际收发的请求与响应，用来补全判定依据
        "packets": evidence.packets(action.exchanges or []),
        "error": action.error,
        "duration_ms": action.duration_ms,
        "created_at": fmt_dt(action.created_at, session_tz()),
    }


def _allows_internal(finding: ScanFinding) -> bool:
    """内网许可跟着所属任务走：任务当时允许内网，其结果才允许再次交互执行。"""
    return bool((finding.task.config_json or {}).get("allow_internal")) if finding.task else False
