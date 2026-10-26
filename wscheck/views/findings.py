from __future__ import annotations

from io import BytesIO

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   send_file, url_for)

from ..extensions import db
from ..models import (PocRegistry, ReviewStatus, ScanFinding, ScanTask, Severity,
                      TargetAsset, TaskLog, VerifyStatus)
from ..services import export
from ..timeutil import session_tz, utcnow
from .common import SEVERITY_RANK, get_or_404, paginate, poc_capabilities

bp = Blueprint("findings", __name__, url_prefix="/findings")

APPEND_ASSET_LIMIT = 500
NOTE_LIMIT = 500
EVIDENCE_LIMIT = 4000
EXPORT_FORMATS = tuple(export.FORMATS)

ACTIONS = {
    "confirm": ReviewStatus.CONFIRMED,
    "false_positive": ReviewStatus.FALSE_POSITIVE,
    "reset": ReviewStatus.PENDING,
}
BATCH_ACTIONS = {**ACTIONS, "delete": None}
SORTS = {
    "newest": ("最新命中", ScanFinding.id.desc()),
    "oldest": ("最早命中", ScanFinding.id.asc()),
    "severity": ("等级从高到低", SEVERITY_RANK.asc()),
}


@bp.route("/")
def list_findings():
    query = ScanFinding.query
    keyword = (request.args.get("q") or "").strip()
    severity = request.args.get("severity")
    review = request.args.get("review")
    verify = request.args.get("verify")
    # 任务 ID 是 UUID 字符串，不能按整数解析，否则筛选会静默失效
    task_id = (request.args.get("task_id") or "").strip() or None
    sort = request.args.get("sort")
    sort = sort if sort in SORTS else "newest"

    if severity in Severity.LABELS:
        query = query.filter(ScanFinding.severity == severity)
    if review in ReviewStatus.LABELS:
        query = query.filter(ScanFinding.review_status == review)
    if verify in VerifyStatus.LABELS:
        query = query.filter(ScanFinding.verify_status == verify)
    if task_id:
        query = query.filter(ScanFinding.task_id == task_id)
    if keyword:
        pattern = f"%{keyword}%"
        query = query.filter(db.or_(ScanFinding.target_url.ilike(pattern), ScanFinding.poc_id.ilike(pattern),
                                    ScanFinding.poc_name.ilike(pattern), ScanFinding.app_name.ilike(pattern)))

    pages = paginate(query.order_by(SORTS[sort][1]), 30)
    return render_template("findings/list.html",
                           pagination=pages,
                           keyword=keyword, severity=severity, review=review, verify=verify,
                           task_id=task_id, sort=sort, sorts={key: label for key, (label, _) in SORTS.items()},
                           # 下拉框只要 id/name，别把 200 条任务的配置与原始输入一起读出来
                           tasks=db.session.query(ScanTask.id, ScanTask.name)
                           .order_by(ScanTask.created_at.desc()).limit(200).all(),
                           severities=Severity.LABELS, reviews=ReviewStatus.LABELS, verifies=VerifyStatus.LABELS,
                           formats=export.FORMATS,
                           poc_caps=poc_capabilities({finding.poc_id for finding in pages.items}))


@bp.get("/<int:finding_id>")
def detail(finding_id):
    finding = get_or_404(ScanFinding, finding_id, "结果")
    return render_template("findings/detail.html", finding=finding, task=finding.task,
                           poc_caps=poc_capabilities([finding.poc_id]))


@bp.post("/<int:finding_id>/review")
def review(finding_id):
    finding = get_or_404(ScanFinding, finding_id, "结果")
    _apply(finding, request.form.get("action", ""), (request.form.get("note") or "").strip())
    db.session.commit()
    flash("结果状态已更新", "success")
    return redirect(request.referrer or url_for("findings.list_findings"))


@bp.post("/<int:finding_id>/delete")
def delete(finding_id):
    finding = get_or_404(ScanFinding, finding_id, "结果")
    db.session.delete(finding)
    db.session.commit()
    flash(f"结果 #{finding_id} 已删除", "success")
    # 详情页删除后返回的 referrer 已经不存在，统一回列表，避免落到 404
    return redirect(url_for("findings.list_findings"))


@bp.post("/batch")
def batch():
    ids = _selected_ids(request.form)
    action = request.form.get("action", "")
    if action not in BATCH_ACTIONS:
        abort(400, f"未知的批量动作: {action}")
    findings = ScanFinding.query.filter(ScanFinding.id.in_(ids)).all()
    if not findings:
        flash("没有可处理的结果，请先勾选要操作的行为", "warning")
        return redirect(request.referrer or url_for("findings.list_findings"))

    if action == "delete":
        for finding in findings:
            db.session.delete(finding)
        db.session.commit()
        flash(f"已删除 {len(findings)} 条结果", "success")
        return redirect(request.referrer or url_for("findings.list_findings"))

    note = (request.form.get("note") or "").strip()
    for finding in findings:
        _apply(finding, action, note)
    db.session.commit()
    flash(f"已批量更新 {len(findings)} 条结果", "success")
    return redirect(request.referrer or url_for("findings.list_findings"))


@bp.route("/append", methods=["GET", "POST"])
def append():
    tasks = (db.session.query(ScanTask.id, ScanTask.name, ScanTask.created_at)
             .order_by(ScanTask.created_at.desc()).limit(200).all())
    pocs = db.session.query(PocRegistry.poc_id, PocRegistry.name).order_by(PocRegistry.poc_id).all()

    def render(form, error: str = ""):
        chosen = (form.get("task_id") or request.args.get("task_id") or "").strip()
        return render_template("findings/append.html", tasks=tasks, pocs=pocs,
                               severities=Severity.LABELS, form=form, error=error,
                               assets=_asset_urls(chosen))

    if request.method != "POST":
        return render({})

    form = request.form
    task = db.session.get(ScanTask, form.get("task_id") or "")
    if task is None:
        return render(form, "请选择要追加结果的任务")
    target_url = (form.get("target_url") or "").strip()[:512]
    if not target_url:
        return render(form, "目标 URL 不能为空")

    verified = bool(form.get("verified"))
    registry = db.session.get(PocRegistry, form.get("poc_id") or "")
    finding = ScanFinding(
        task_id=task.id,
        target_url=target_url,
        poc_id=(form.get("poc_id") or "manual")[:255],
        poc_name=(registry.name if registry else form.get("poc_name") or "人工补充")[:255],
        severity=form.get("severity") if form.get("severity") in Severity.LABELS else "medium",
        app_name=(registry.app_name if registry else "") or "",
        evidence={"detail": {"note": (form.get("evidence") or "").strip()[:EVIDENCE_LIMIT]},
                  "error": ""},
        verify_status="confirmed" if verified else "unverified",
        verify_detail="人工补充并确认" if verified else "人工补充，未标记为已确认",
        review_status=ReviewStatus.CONFIRMED,
        review_note=(form.get("note") or "").strip()[:NOTE_LIMIT],
        source="manual_append",
        created_at=utcnow(),
        reviewed_at=utcnow(),
    )
    db.session.add(finding)
    db.session.add(TaskLog(task_id=task.id, level="info",
                           message=f"人工补充结果：{finding.target_url} / {finding.poc_id}",
                           created_at=utcnow()))
    db.session.commit()
    flash("结果已追加到任务", "success")
    return redirect(url_for("tasks.detail", task_id=task.id, tab="findings"))


@bp.post("/export")
def export_selected():
    """把勾选的结果单独导出一份，不必先把整个任务导出再手工挑行。"""
    fmt = request.form.get("fmt", "csv")
    if fmt not in EXPORT_FORMATS:
        abort(400, f"不支持的导出格式: {fmt}")
    ids = _selected_ids(request.form)
    findings = (ScanFinding.query.filter(ScanFinding.id.in_(ids))
                .order_by(ScanFinding.task_id, ScanFinding.id).all())
    if not findings:
        flash("没有可导出的结果，请先勾选要导出的行为", "warning")
        return redirect(request.referrer or url_for("findings.list_findings"))

    task_ids = {finding.task_id for finding in findings}
    tasks = (ScanTask.query.filter(ScanTask.id.in_(task_ids))
             .order_by(ScanTask.created_at).all())
    assets = export.collect_assets([task.id for task in tasks])
    filename, mimetype, content = export.render(tasks, findings, assets, fmt,
                                                f"选中结果 {len(findings)} 条", session_tz())
    return send_file(BytesIO(content.encode("utf-8")), mimetype=mimetype,
                     as_attachment=True, download_name=filename)


def _selected_ids(form) -> list[int]:
    # 浏览器可同时提交复选框与 JS 补的 hidden 字段，统一去重
    return list(dict.fromkeys(int(value) for value in form.getlist("ids") if str(value).isdigit()))


def _asset_urls(task_id: str) -> list[str]:
    """补充结果时给出该任务已采集的资产 URL，避免手抄长链接。"""
    if not task_id:
        return []
    rows = (db.session.query(TargetAsset.url)
            .filter(TargetAsset.task_id == task_id).order_by(TargetAsset.url)
            .limit(APPEND_ASSET_LIMIT).all())
    return [row[0] for row in rows]


def _apply(finding: ScanFinding, action: str, note: str) -> None:
    if action not in ACTIONS:
        abort(400, f"未知的复核动作: {action}")
    finding.review_status = ACTIONS[action]
    # 批量操作时说明框常常是空的，不能把已有的复核说明一起抹掉
    if note:
        finding.review_note = note[:NOTE_LIMIT]
    finding.reviewed_at = utcnow()
