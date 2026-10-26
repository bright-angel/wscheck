from __future__ import annotations

from datetime import timedelta
from io import BytesIO
from types import SimpleNamespace

from flask import (Blueprint, abort, current_app, flash, jsonify, redirect, render_template,
                   request, send_file, url_for)
from sqlalchemy import func

from ..extensions import db
from ..models import (FingerprintRule, PocRegistry, ReviewStatus, ScanFinding, ScanTask,
                      Severity, TargetAsset, TaskLog, TaskStatus)
from ..services import export, fofa, taskmgr
from ..services.fingerprint import directory
from ..services.taskmgr import TaskOptions
from ..timeutil import session_tz, utcnow
from ..util import int_value
from .common import SEVERITY_RANK, get_or_404, paginate, poc_capabilities

bp = Blueprint("tasks", __name__, url_prefix="/tasks")

TERMINAL = (TaskStatus.DONE, TaskStatus.PARTIAL, TaskStatus.FAILED, TaskStatus.CANCELED)
PICKER_LIMIT = 50
PICKED_LIMIT = 500
FINDING_COUNT = (db.select(func.count(ScanFinding.id))
                 .where(ScanFinding.task_id == ScanTask.id)
                 .correlate(ScanTask).scalar_subquery())
SORTS = {
    "newest": ("最新创建", ScanTask.created_at.desc()),
    "oldest": ("最早创建", ScanTask.created_at.asc()),
    "findings": ("结果最多", FINDING_COUNT.desc()),
}
TABS = ("findings", "assets", "logs")


@bp.route("/")
@bp.route("")
def list_tasks():
    query = ScanTask.query
    status = request.args.get("status")
    keyword = (request.args.get("q") or "").strip()
    days = int_value(request.args.get("days"), 0, 0, 3650)
    severity = request.args.get("severity")
    sort = request.args.get("sort")
    sort = sort if sort in SORTS else "newest"

    if status in TaskStatus.LABELS:
        query = query.filter(ScanTask.status == status)
    if severity in Severity.LABELS:
        # 只看跑出过某个等级的任务；与列表计数口径一致，排除误报
        query = query.filter(db.select(ScanFinding.id).where(
            ScanFinding.task_id == ScanTask.id, ScanFinding.severity == severity,
            ScanFinding.review_status != ReviewStatus.FALSE_POSITIVE).exists())
    if keyword:
        pattern = f"%{keyword}%"
        query = query.filter(db.or_(ScanTask.name.ilike(pattern), ScanTask.id.ilike(pattern),
                                    ScanTask.input_raw.ilike(pattern)))
    if days:
        query = query.filter(ScanTask.created_at >= utcnow() - timedelta(days=days))
    if request.args.get("only_active"):
        query = query.filter(ScanTask.status.in_(TaskStatus.ACTIVE))

    pagination = paginate(query.order_by(SORTS[sort][1]))
    return render_template("tasks/list.html", pagination=pagination,
                           counts=_finding_stats([task.id for task in pagination.items]),
                           statuses=TaskStatus.LABELS, days=days, keyword=keyword,
                           severity=severity, severities=Severity.LABELS,
                           sort=sort, sorts={key: label for key, (label, _) in SORTS.items()},
                           selected_status=status)


@bp.route("/new", methods=["GET", "POST"])
def new():
    posted = request.method == "POST"
    context = {
        "rule_total": FingerprintRule.query.filter_by(enabled=1).count(),
        "picked_rules": _kept(FingerprintRule, FingerprintRule.id, request.form.getlist("fingerprint_ids")) if posted else [],
        "picked_pocs": _kept(PocRegistry, PocRegistry.poc_id, request.form.getlist("poc_ids")) if posted else [],
        "defaults": dict(current_app.config["SCAN_DEFAULTS"]),
        "scan_modes": taskmgr.SCAN_MODES,
        "dir_dict": _dir_dict(),
        "fofa_ready": fofa.is_configured(),
        "fofa_limit": fofa.MAX_RESULTS,
        "form": {},
        "error": "",
    }
    if not posted:
        return render_template("tasks/form.html", **context)

    form = request.form
    raw = form.get("input", "").strip()
    options = TaskOptions.from_form(form, context["defaults"])
    if not raw:
        context.update(error="请输入至少一个目标", form=form)
        return render_template("tasks/form.html", **context)
    try:
        task = taskmgr.create_task(current_app, form.get("name", "").strip(), raw, options)
    except Exception as error:
        # 建任务要落库并拉起执行线程，失败时把已填的目标列表留在表单里，不让用户重敲
        db.session.rollback()
        current_app.logger.exception("创建任务失败: %s", error)
        context.update(error=f"任务创建失败：{error}", form=form)
        return render_template("tasks/form.html", **context)
    return redirect(url_for("tasks.detail", task_id=task.id))


@bp.post("/fofa")
def fofa_import():
    """按 FOFA 查询语句返回目标 URL，由表单脚本追加到目标列表。"""
    if not fofa.is_configured():
        return jsonify(error="尚未配置 FOFA API Key，请到全局设置中填写"), 400
    payload = request.get_json(silent=True)
    payload = payload if isinstance(payload, dict) else {}
    try:
        limit = int(payload.get("limit") or 50)
    except (TypeError, ValueError):
        limit = 50
    result = fofa.search(str(payload.get("query") or ""), limit)
    if result.error:
        return jsonify(error=result.error), 502
    return jsonify(urls=result.urls, count=len(result.urls), total=result.total)


@bp.get("/picker")
def picker():
    """任务表单的规则/POC 搜索候选，规则数量大时避免整页渲染。"""
    keyword = (request.args.get("q") or "").strip()
    pattern = f"%{keyword}%"

    if (request.args.get("kind") or "") == "rule":
        query = FingerprintRule.query.filter(FingerprintRule.enabled == 1)
        if keyword:
            query = query.filter(db.or_(FingerprintRule.id.ilike(pattern),
                                        FingerprintRule.name.ilike(pattern),
                                        FingerprintRule.app_name.ilike(pattern)))
        rows = query.order_by(FingerprintRule.name).limit(PICKER_LIMIT).all()
        items = [{"value": r.id, "label": r.name, "extra": r.app_name} for r in rows]
    else:
        query = PocRegistry.query.filter(PocRegistry.enabled == 1)
        if keyword:
            query = query.filter(db.or_(PocRegistry.poc_id.ilike(pattern),
                                        PocRegistry.name.ilike(pattern),
                                        PocRegistry.app_name.ilike(pattern)))
        rows = query.order_by(PocRegistry.name).limit(PICKER_LIMIT).all()
        items = [{"value": p.poc_id, "label": p.name, "extra": _poc_hint(p)} for p in rows]
    return jsonify(items)


def _poc_hint(poc: PocRegistry) -> str:
    """候选项后缀：把「为什么默认不跑」写清楚，省得勾完才发现没执行。"""
    return "、".join(filter(None, (poc.app_name, "" if poc.loadable else "引擎不加载",
                                   poc.heavy_reason,
                                   "需要 OOB" if poc.needs_dnslog else "")))


def _dir_dict() -> dict:
    """表单里展示目录字典规模，字典缺失时提示而不是等任务跑起来才发现。"""
    path = current_app.config["DIR_DICT_PATH"]
    entries = directory.load_rules(path)
    return {"path": path, "apps": len(entries),
            "paths": sum(len(paths) for _, paths in entries)}


def _kept(model, column, values: list[str]) -> list[dict]:
    """回显已勾选的规则/POC：只保留库中仍存在的 id，并附带展示名。"""
    picked = list(dict.fromkeys(values))[:PICKED_LIMIT]
    if not picked:
        return []
    labels = {getattr(row, column.name): row.name
              for row in db.session.query(model).filter(column.in_(picked)).all()}
    return [{"value": value, "label": labels[value]} for value in picked if value in labels]


@bp.get("/<task_id>")
def detail(task_id):
    task = get_or_404(ScanTask, task_id, "任务")
    tab = request.args.get("tab")
    tab = tab if tab in TABS else "findings"
    # 导航栏只要总数；只有当前标签页需要取行数据，避免一次查三张大表
    totals = {model.__name__: _task_count(model, task.id)
              for model in (ScanFinding, TargetAsset, TaskLog)}
    findings = SimpleNamespace(total=totals["ScanFinding"])
    assets = SimpleNamespace(total=totals["TargetAsset"])
    logs = SimpleNamespace(total=totals["TaskLog"])
    poc_caps = {}
    if tab == "findings":
        findings = paginate(ScanFinding.query.filter_by(task_id=task.id).order_by(ScanFinding.id), 30)
        poc_caps = poc_capabilities({finding.poc_id for finding in findings.items})
    elif tab == "assets":
        assets = paginate(TargetAsset.query.filter_by(task_id=task.id).order_by(TargetAsset.id), 50)
    else:
        logs = paginate(TaskLog.query.filter_by(task_id=task.id).order_by(TaskLog.id.desc()), 100)
    return render_template(
        "tasks/detail.html",
        task=task,
        tab=tab,
        assets=assets,
        findings=findings,
        logs=logs,
        severity_counts=_severity_counts(task.id),
        poc_caps=poc_caps,
        scan_modes=taskmgr.SCAN_MODES,
        formats=export.FORMATS,
    )


@bp.get("/<task_id>/summary")
def summary(task_id):
    task = get_or_404(ScanTask, task_id, "任务")
    return jsonify({
        "status": task.status,
        "status_label": task.status_label,
        "progress": task.progress,
        "findings": ScanFinding.query.filter_by(task_id=task.id).count(),
        "assets": TargetAsset.query.filter_by(task_id=task.id).count(),
        "severity_counts": _severity_counts(task.id),
        "finished": task.status in TERMINAL,
        "error": task.error_message,
    })


@bp.post("/<task_id>/cancel")
def cancel(task_id):
    task = get_or_404(ScanTask, task_id, "任务")
    # 终态任务不能被一次迟到的取消请求改写；排队中的任务也应允许取消
    if task.status not in TaskStatus.ACTIVE:
        flash("任务已结束，无需取消", "warning")
    elif taskmgr.cancel(task.id):
        flash("已请求取消，当前批次结束后停止", "warning")
    else:
        flash("任务状态已变化，请刷新后查看", "warning")
    return redirect(url_for("tasks.detail", task_id=task.id))


@bp.post("/<task_id>/delete")
def delete(task_id):
    task = get_or_404(ScanTask, task_id, "任务")
    if task.is_active:
        flash("任务仍在运行，请先取消后再删除", "warning")
        return redirect(url_for("tasks.detail", task_id=task.id))
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for("tasks.list_tasks"))


@bp.post("/<task_id>/retry")
def retry(task_id):
    source = get_or_404(ScanTask, task_id, "任务")
    options = taskmgr.options_from_config(source.config_json)
    task = taskmgr.create_task(current_app, f"{source.name} · 重试", source.input_raw, options)
    return redirect(url_for("tasks.detail", task_id=task.id))


@bp.get("/<task_id>/export")
def download(task_id):
    task = get_or_404(ScanTask, task_id, "任务")
    fmt = request.args.get("fmt", "html")
    if fmt not in export.FORMATS:
        abort(400, "不支持的导出格式")
    findings = export.collect([task.id], include_false_positive=request.args.get("all") == "1")
    assets = export.collect_assets([task.id])
    filename, mimetype, content = export.render([task], findings, assets, fmt,
                                                task.name or task.id[:8], session_tz())
    # 任务名可能含中文，交给 send_file 生成 RFC 5987 的 filename*，不能手拼 latin-1 头
    return send_file(BytesIO(content.encode("utf-8")), mimetype=mimetype,
                     as_attachment=True, download_name=filename)


def _task_count(model, task_id: str) -> int:
    return db.session.scalar(
        db.select(func.count()).select_from(model).where(model.task_id == task_id)) or 0


def _severity_counts(task_id: str) -> dict:
    counts = {level: 0 for level in Severity.ORDER}
    rows = (db.session.query(ScanFinding.severity, func.count(ScanFinding.id))
            .filter(ScanFinding.task_id == task_id).group_by(ScanFinding.severity).all())
    for level, count in rows:
        counts[level] = count
    return counts


def _finding_stats(task_ids) -> dict:
    """按任务汇总有效结果数（排除误报）与命中的最高等级。"""
    if not task_ids:
        return {}
    rows = (db.session.query(ScanFinding.task_id, func.count(ScanFinding.id), func.min(SEVERITY_RANK))
            .filter(ScanFinding.task_id.in_(task_ids),
                    ScanFinding.review_status != ReviewStatus.FALSE_POSITIVE)
            .group_by(ScanFinding.task_id).all())
    return {task_id: {"count": count,
                      "top": Severity.ORDER[rank] if rank < len(Severity.ORDER) else ""}
            for task_id, count, rank in rows}
