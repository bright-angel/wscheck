from __future__ import annotations

import itertools
import os

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from ..extensions import db
from ..models import PocRegistry, ScanFinding, Severity
from ..services import settings
from ..services.poc import indexer, runner, sync
from ..services.fingerprint import app_rule_counts, invalidate
from .common import get_or_404, paginate

bp = Blueprint("pocs", __name__, url_prefix="/pocs")


@bp.route("/")
def list_pocs():
    query = PocRegistry.query
    keyword = (request.args.get("q") or "").strip()
    severity = request.args.get("severity")
    state = request.args.get("state")
    if keyword:
        pattern = f"%{keyword}%"
        query = query.filter(db.or_(PocRegistry.poc_id.ilike(pattern), PocRegistry.name.ilike(pattern),
                                    PocRegistry.app_name.ilike(pattern)))
    if severity in Severity.LABELS:
        query = query.filter(PocRegistry.severity == severity)
    if state == "on":
        query = query.filter(PocRegistry.enabled == 1)
    elif state == "off":
        query = query.filter(PocRegistry.enabled == 0)
    elif state == "unloadable":
        query = query.filter(PocRegistry.loadable == 0)

    pagination = paginate(query.order_by(PocRegistry.app_name, PocRegistry.poc_id), 30)
    counts = app_rule_counts(poc.app_name for poc in pagination.items)
    return render_template("pocs/list.html", pagination=pagination,
                           linked={poc.poc_id: counts.get(poc.app_name, 0) for poc in pagination.items},
                           keyword=keyword, severity=severity, state=state,
                           severities=Severity.LABELS,
                           unloadable_count=db.session.query(PocRegistry).filter_by(loadable=0).count(),
                           pocsuite_available=runner.is_available(),
                           poc_dir=current_app.config["POC_DIR"],
                           repo_url=settings.get("poc_repo_url"),
                           repo_ref=settings.get("poc_repo_ref"),
                           repo_state=sync.last_sync(current_app.config["POC_SYNC_STATE"]))


@bp.get("/<poc_id>")
def detail(poc_id):
    """单个 POC 的元数据、参数与脚本片段，便于判断它到底会对目标做什么。"""
    poc = get_or_404(PocRegistry, poc_id, "POC")
    query = ScanFinding.query.filter_by(poc_id=poc.poc_id)
    return render_template("pocs/detail.html", poc=poc, oob_ready=settings.oob_ready(),
                           linked_rule_count=app_rule_counts([poc.app_name]).get(poc.app_name, 0),
                           hits=query.order_by(ScanFinding.id.desc()).limit(10).all(),
                           hit_count=query.count(), source=_source(poc.file_path))


@bp.post("/<poc_id>/toggle")
def toggle(poc_id):
    poc = get_or_404(PocRegistry, poc_id, "POC")
    poc.enabled = 0 if poc.enabled else 1
    db.session.commit()
    return redirect(request.referrer or url_for("pocs.list_pocs"))


@bp.post("/reindex")
def reindex():
    stats = indexer.sync_registry(current_app.config["POC_DIR"], db.session)
    if stats["missing"]:
        flash(f"POC 目录不存在或不可读：{current_app.config['POC_DIR']}，现有索引保持不变",
              "danger")
        return redirect(request.referrer or url_for("pocs.list_pocs"))
    invalidate()
    flash(f"POC 索引已重建：新增 {stats['added']}，更新 {stats['updated']}，"
          f"移除 {stats['removed']}，共 {stats['total']} 个文件；"
          f"其中 {stats['unloadable']} 个不会被引擎加载", "success")
    return redirect(request.referrer or url_for("pocs.list_pocs"))


@bp.post("/sync")
def sync_repo():
    """从设置里指定的 GitHub 仓库拉取 POC，落盘后立即重建索引。"""
    cfg = sync.config_from_settings()
    if not cfg.repo_url:
        flash("请先在「设置 → POC 仓库同步」中填写仓库地址", "warning")
        return redirect(url_for("settings.index") + "#group-poc_repo")
    if runner.RUN_LOCK.locked():
        flash("POC 引擎正在执行任务，请等任务结束后再同步仓库", "warning")
        return redirect(request.referrer or url_for("pocs.list_pocs"))
    try:
        result = sync.sync_from_repo(
            cfg, current_app.config["POC_DIR"],
            current_app.config["POC_SYNC_STATE"],
            current_app.config["POC_SYNC_BACKUP_DIR"],
            proxies=settings.http_proxies(), force=True,
        )
    except (sync.SyncError, OSError) as error:
        flash(f"POC 仓库同步失败：{error}", "danger")
        return redirect(request.referrer or url_for("pocs.list_pocs"))

    stats = indexer.sync_registry(current_app.config["POC_DIR"], db.session)
    invalidate()
    if result.unchanged:
        flash(f"仓库 {result.slug}@{result.ref} 已是最新（{result.commit[:7]}），"
              f"本地共 {stats['total']} 个 POC", "info")
    else:
        flash(f"已从 {result.slug}@{result.ref} 同步完成：写入 {result.written} 个文件，"
              f"移除 {result.removed} 个，提交 {result.commit[:7]}；"
              f"索引新增 {stats['added']}、更新 {stats['updated']}、移除 {stats['removed']}", "success")
    if result.skipped:
        names = "、".join(result.skipped[:5]) + (" 等" if len(result.skipped) > 5 else "")
        flash(f"有 {len(result.skipped)} 个文件在写入时消失，已跳过：{names}。"
              "通常是本机安全软件把 POC 当成恶意文件隔离，请把 POC 目录加入信任后重新同步", "warning")
    return redirect(request.referrer or url_for("pocs.list_pocs"))


SOURCE_LINES = 220


def _source(path: str) -> str:
    """展示 POC 脚本前若干行：路径来自本地索引而非请求参数，只读不执行。"""
    if not path or not os.path.isfile(path):
        return ""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return "".join(itertools.islice(handle, SOURCE_LINES))
    except OSError:
        return ""
