from __future__ import annotations

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import FingerprintRule
from ..services import normalize, settings
from ..services.fingerprint import (FingerprintEngine, ParseError, describe, engine_from_db,
                                    invalidate, parse, probe)
from ..services.fingerprint import sync as rules_sync
from ..timeutil import utcnow
from ..util import int_value
from .common import get_or_404, paginate

bp = Blueprint("fingerprints", __name__, url_prefix="/fingerprints")

ADHOC_RULE_ID = "__adhoc__"
# 单次测试会真实访问每个目标（探测超时 6s），不限行数能把页面挂死
TEST_URL_LIMIT = 20


@bp.route("/")
def list_rules():
    query = FingerprintRule.query
    keyword = (request.args.get("q") or "").strip()
    state = request.args.get("state")
    if keyword:
        pattern = f"%{keyword}%"
        query = query.filter(db.or_(FingerprintRule.id.ilike(pattern), FingerprintRule.name.ilike(pattern),
                                    FingerprintRule.expr.ilike(pattern), FingerprintRule.app_name.ilike(pattern)))
    if state == "on":
        query = query.filter(FingerprintRule.enabled == 1)
    elif state == "off":
        query = query.filter(FingerprintRule.enabled == 0)

    pagination = paginate(query.order_by(FingerprintRule.id))
    return render_template("fingerprints/list.html", pagination=pagination, keyword=keyword, state=state,
                           broken={rule.id: _check(rule.expr) for rule in pagination.items},
                           rules_repo_url=settings.get("rules_repo_url"),
                           rules_repo_ref=settings.get("rules_repo_ref"),
                           rules_state=rules_sync.last_sync(current_app.config["RULES_SYNC_STATE"]))


@bp.route("/new", methods=["GET", "POST"])
@bp.route("/<rule_id>/edit", methods=["GET", "POST"])
def edit(rule_id: str = ""):
    rule = get_or_404(FingerprintRule, rule_id, "规则") if rule_id else None

    if request.method != "POST":
        return render_template("fingerprints/form.html", data=_as_data(rule), editing=bool(rule))

    form = request.form
    new_id = (form.get("id") or "").strip() or (rule.id if rule else "")
    error = _validate(new_id, form.get("expr", "").strip(), rule)
    if error:
        flash(error, "danger")
        return render_template("fingerprints/form.html", data=_as_data(form), editing=bool(rule))

    rule_was_saved = rule is not None
    if rule is None:
        rule = FingerprintRule(id=new_id, created_at=utcnow())
        db.session.add(rule)
    rule.id = new_id
    rule.name = (form.get("name") or new_id).strip()
    rule.expr = form.get("expr", "").strip()
    rule.app_name = (form.get("app_name") or "").strip()
    rule.threshold = int_value(form.get("threshold"), 30, 0)
    rule.enabled = 1 if form.get("enabled") else 0
    rule.note = (form.get("note") or "").strip()
    rule.updated_at = utcnow()
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash(f"规则 ID 已存在：{new_id}", "danger")
        return render_template("fingerprints/form.html", data=_as_data(form),
                               editing=rule_was_saved)
    invalidate()
    flash("规则已保存", "success")
    return redirect(url_for("fingerprints.list_rules"))


@bp.post("/<rule_id>/toggle")
def toggle(rule_id):
    rule = get_or_404(FingerprintRule, rule_id, "规则")
    rule.enabled = 0 if rule.enabled else 1
    rule.updated_at = utcnow()
    db.session.commit()
    invalidate()
    return redirect(request.referrer or url_for("fingerprints.list_rules"))


@bp.post("/<rule_id>/delete")
def delete(rule_id):
    db.session.delete(get_or_404(FingerprintRule, rule_id, "规则"))
    db.session.commit()
    invalidate()
    flash("规则已删除", "success")
    return redirect(url_for("fingerprints.list_rules"))


@bp.post("/reload")
def reload_rules():
    invalidate()
    engine = engine_from_db()
    flash(f"规则已热重载：启用 {len(engine.rules)} 条，解析错误 {len(engine.errors)} 条", "success")
    return redirect(request.referrer or url_for("fingerprints.list_rules"))


@bp.post("/sync")
def sync_repo():
    """从设置里指定的 GitHub 仓库拉取指纹规则，落盘后导入数据库。"""
    cfg = rules_sync.config_from_settings()
    if not cfg.repo_url:
        flash("请先在「设置 → 指纹规则仓库同步」中填写仓库地址", "warning")
        return redirect(url_for("settings.index") + "#group-rules_repo")
    try:
        result, stats = rules_sync.sync_rules(
            cfg, current_app.config["RULES_DIR"],
            current_app.config["RULES_SYNC_STATE"],
            current_app.config["RULES_SYNC_BACKUP_DIR"],
            proxies=settings.http_proxies(), force=True,
        )
    except (rules_sync.SyncError, OSError) as error:
        flash(f"指纹规则仓库同步失败：{error}", "danger")
        return redirect(request.referrer or url_for("fingerprints.list_rules"))

    invalidate()
    if result.unchanged:
        flash(f"规则仓库 {result.slug}@{result.ref} 已是最新（{result.commit[:7]}）", "info")
    else:
        parts = [f"已从 {result.slug}@{result.ref} 同步完成：写入 {result.written} 个文件，"
                 f"移除 {result.removed} 个",
                 f"规则新增 {stats['added']}、更新 {stats['updated']}、删除 {stats['removed']}"]
        if stats["invalid"]:
            parts.append(f"忽略 {stats['invalid']} 条无效条目")
        flash("；".join(parts) + f"（提交 {result.commit[:7]}）", "success")
        if result.skipped:
            names = "、".join(result.skipped[:5]) + (" 等" if len(result.skipped) > 5 else "")
            flash(f"有 {len(result.skipped)} 个文件在写入时消失，已跳过：{names}。"
                  "通常是本机安全软件拦截删除，请把规则目录加入信任后重新同步", "warning")
    return redirect(request.referrer or url_for("fingerprints.list_rules"))


@bp.route("/test", methods=["GET", "POST"])
def test():
    expr = (request.values.get("expr") or 'title="后台"').strip()
    urls = _lines(request.values.get("urls"))
    kept = urls[:TEST_URL_LIMIT]
    allow_internal = request.values.get("allow_internal") == "on"
    threshold = int_value(request.values.get("threshold"), 30, 0)
    output = {"expr": expr, "threshold": threshold, "parse_error": _check(expr),
              "allow_internal": allow_internal, "skipped_lines": max(0, len(urls) - len(kept)),
              "results": []}

    if request.method == "POST" and not output["parse_error"]:
        # 打开测试页不需要全量规则；只有真正测试时才构建/复用引擎
        engine = engine_from_db()
        rule = FingerprintRule(id=ADHOC_RULE_ID, name="临时表达式", expr=expr,
                               threshold=threshold, app_name="", enabled=1)
        scratch = FingerprintEngine([rule], current_app.config["SIGNAL_WEIGHTS"])
        for url in kept:
            # 测试页与扫描共用同一条内网红线：本工具不默认探测内网，需要用户显式勾选
            if not allow_internal and normalize.is_internal_url(url):
                output["results"].append({"url": url, "error": "内网地址，勾选「允许内网」后再测试"})
                continue
            output["results"].append(_test_one(scratch, engine, rule, url))

    return render_template("fingerprints/test.html", output=output, limit=TEST_URL_LIMIT)


def _test_one(scratch: FingerprintEngine, engine: FingerprintEngine, rule, url: str) -> dict:
    result = probe(url, timeout=6, user_agent=settings.user_agent(), proxies=settings.http_proxies())
    if result.error:
        return {"url": url, "error": result.error}

    signals = {name: (value[:160] + "…") if len(value) > 160 else value
               for name, value in result.signals().items() if value}
    matched = engine.match(result.signals())
    return {
        "url": url,
        "final_url": result.final_url,
        "status_code": result.status_code,
        "title": result.title,
        "server": result.server,
        "signals": signals,
        "ast": describe(parse(rule.expr)),
        "evaluation": scratch.evaluate(rule, result.signals()).to_dict(),
        "hits": [{"id": rid, "name": engine.label(rid), "score": int(r.score), "threshold": r.threshold}
                 for rid, r in matched.items()],
    }


def _check(expr: str) -> str:
    try:
        parse(expr)
    except ParseError as error:
        return str(error)
    return ""


def _validate(rule_id: str, expr: str, existing: FingerprintRule | None) -> str:
    if not rule_id:
        return "规则 ID 不能为空"
    if not expr:
        return "表达式不能为空"
    error = _check(expr)
    if error:
        return f"表达式有误：{error}"
    # 重命名时也要查重：改成已存在的 ID 会触发主键冲突
    if rule_id != (existing.id if existing else None) and db.session.get(FingerprintRule, rule_id):
        return f"规则 ID 已存在：{rule_id}"
    return ""


def _lines(value) -> list[str]:
    return [line.strip() for line in (value or "").replace("\r", "\n").split("\n") if line.strip()]


def _as_data(source) -> dict:
    if source is None:
        return {}
    keys = ("id", "name", "expr", "app_name", "threshold", "note", "enabled")
    if hasattr(source, "getlist"):
        return {key: source.get(key, "") for key in keys}
    return {key: getattr(source, key, "") for key in keys}
