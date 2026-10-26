from __future__ import annotations

import os

from flask import (Blueprint, abort, current_app, flash, redirect, render_template,
                   request, send_file, url_for)
from sqlalchemy import func

from ..extensions import db
from ..models import Report, ReviewStatus, ScanFinding, ScanTask
from ..services import export
from ..timeutil import session_tz, utcnow
from .common import get_or_404, paginate

bp = Blueprint("reports", __name__, url_prefix="/reports")


@bp.route("/")
def list_reports():
    tasks = (db.session.query(ScanTask.id, ScanTask.name, ScanTask.created_at)
             .order_by(ScanTask.created_at.desc()).limit(200).all())
    counts = {}
    if tasks:
        # 报告默认排除误报，列表上的结果数也要用同一口径；一次分组统计代替逐任务 count
        rows = (db.session.query(ScanFinding.task_id, func.count(ScanFinding.id))
                .filter(ScanFinding.task_id.in_([task.id for task in tasks]),
                        ScanFinding.review_status != ReviewStatus.FALSE_POSITIVE)
                .group_by(ScanFinding.task_id).all())
        counts = dict(rows)
    pages = paginate(Report.query.order_by(Report.id.desc()), 20)
    return render_template("reports/list.html", reports=pages.items, pagination=pages,
                           tasks=tasks, counts=counts, formats=export.FORMATS)


@bp.post("/create")
def create():
    # 表单可能被重复提交或任务已被删除，先按库中存在的任务过滤
    task_ids = list(dict.fromkeys(request.form.getlist("task_ids")))[:200]
    requested = [f for f in request.form.getlist("formats") if f in export.FORMATS]
    if not task_ids:
        flash("请至少选择一个任务", "danger")
        return redirect(url_for("reports.list_reports"))
    if not requested:
        # 过去这里静默退回 HTML，用户勾了 CSV 却拿不到文件也不知道为什么
        flash("请至少选择一种报告格式", "danger")
        return redirect(url_for("reports.list_reports"))

    existing = {row[0] for row in db.session.query(ScanTask.id).filter(ScanTask.id.in_(task_ids))}
    valid_ids = [task_id for task_id in task_ids if task_id in existing]
    if not valid_ids:
        flash("所选任务已不存在，请刷新页面后重新选择", "danger")
        return redirect(url_for("reports.list_reports"))

    # 与 Report.name 列宽保持一致，超长输入截断而不是留给数据库报错
    name = ((request.form.get("name") or "").strip()
            or f"合并报告-{utcnow():%Y%m%d-%H%M%S}")[:160]
    try:
        report = export.save_bundle(current_app, name, valid_ids, requested, session_tz())
    except OSError as error:
        current_app.logger.exception("生成报告失败: %s", error)
        flash(f"报告生成失败（{type(error).__name__}），详情见服务端日志", "danger")
        return redirect(url_for("reports.list_reports"))

    if len(valid_ids) != len(task_ids):
        flash(f"有 {len(task_ids) - len(valid_ids)} 个任务已不存在，已自动忽略", "warning")
    flash(f"报告已生成：{report.name}（{report.finding_count} 条结果，"
          f"格式 {'、'.join(export.FORMATS[fmt] for fmt in requested)}）", "success")
    return redirect(url_for("reports.list_reports"))


@bp.get("/<int:report_id>/download")
def download(report_id):
    report = get_or_404(Report, report_id, "报告")
    fmt = request.args.get("fmt", "html")
    path = (report.files or {}).get(fmt)
    if not path or not os.path.isfile(path):
        abort(404, "报告文件不存在，可能已被清理")
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@bp.post("/<int:report_id>/delete")
def delete(report_id):
    report = get_or_404(Report, report_id, "报告")
    failed = 0
    paths = [path for path in (report.files or {}).values() if path]
    for path in paths:
        try:
            os.remove(path)
        except FileNotFoundError:
            continue
        except OSError as error:
            failed += 1
            current_app.logger.warning("删除报告文件失败 %s: %s", path, error)
    for directory in {os.path.dirname(path) for path in paths}:
        try:
            os.rmdir(directory)
        except OSError:
            pass  # 目录非空或已被删除都不影响记录清理
    db.session.delete(report)
    db.session.commit()
    if failed:
        flash(f"报告记录已删除，但有 {failed} 个文件未能清理，请检查服务端日志", "warning")
    else:
        flash("报告已删除", "success")
    return redirect(url_for("reports.list_reports"))
