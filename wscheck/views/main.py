from __future__ import annotations

from flask import Blueprint, redirect, render_template, request, session, url_for
from sqlalchemy import func

from ..extensions import db
from ..models import FingerprintRule, PocRegistry, ReviewStatus, ScanFinding, ScanTask, Severity, TaskStatus
from ..services.poc import runner
from ..timeutil import TIMEZONES

bp = Blueprint("main", __name__)


@bp.route("/")
def overview():
    # 一次分组查出各等级的有效结果数，避免按等级逐个 count
    rows = (db.session.query(ScanFinding.severity, func.count(ScanFinding.id))
            .filter(ScanFinding.review_status != ReviewStatus.FALSE_POSITIVE)
            .group_by(ScanFinding.severity).all())
    counts = dict(rows)
    recent_tasks = ScanTask.query.order_by(ScanTask.created_at.desc()).limit(8).all()
    return render_template(
        "overview.html",
        total_tasks=ScanTask.query.count(),
        active_tasks=ScanTask.query.filter(ScanTask.status.in_(TaskStatus.ACTIVE)).count(),
        total_findings=sum(counts.values()),
        pending_review=ScanFinding.query.filter_by(review_status=ReviewStatus.PENDING).count(),
        severity_counts={level: counts.get(level, 0) for level in Severity.ORDER},
        rule_count=FingerprintRule.query.filter_by(enabled=1).count(),
        poc_count=PocRegistry.query.filter_by(enabled=1).count(),
        pocsuite_available=runner.is_available(),
        recent_tasks=recent_tasks,
        finding_counts=_finding_counts([task.id for task in recent_tasks]),
        top_findings=ScanFinding.query.filter(ScanFinding.review_status != ReviewStatus.FALSE_POSITIVE)
        .order_by(ScanFinding.id.desc()).limit(8).all(),
    )


def _finding_counts(task_ids) -> dict:
    """按任务汇总结果数：模板里 task.findings|length 会把每条结果（含证据 JSON）都加载出来。"""
    if not task_ids:
        return {}
    rows = (db.session.query(ScanFinding.task_id, func.count(ScanFinding.id))
            .filter(ScanFinding.task_id.in_(task_ids))
            .group_by(ScanFinding.task_id).all())
    return dict(rows)


@bp.post("/timezone")
def set_timezone():
    zone = request.form.get("tz")
    if zone in {name for name, _label in TIMEZONES}:
        session["tz"] = zone
    return redirect(request.referrer or url_for("main.overview"))
