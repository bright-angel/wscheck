"""全局设置页：代理、OOB、POC / 规则仓库、请求参数与 POC 默认参数，附连通性自测。"""

from __future__ import annotations

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from ..extensions import db
from ..models import PocRegistry
from ..services import settings
from ..services.fingerprint import sync as rules_sync
from ..services.poc import runner, sync

bp = Blueprint("settings", __name__, url_prefix="/settings")


@bp.route("/", methods=["GET", "POST"])
@bp.route("", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        form = request.form
        if form.get("test"):
            return _run_test(form["test"], form)
        if not form.get("settings_form"):
            # 只认设置表单自己的提交：表单字段是整体覆盖写入的，误提交的半截表单会把配置清空
            flash("提交内容不是设置表单，已忽略", "warning")
            return redirect(url_for("settings.index"))
        errors = settings.save(form)
        if errors:
            for error in errors:
                flash(error, "danger")
        else:
            flash("设置已保存，下一个任务或下一次交互执行生效", "success")
        return redirect(url_for("settings.index"))

    values = settings.values()
    return render_template("settings.html",
                           groups=settings.GROUPS,
                           values=values,
                           summary=settings.summary(values),
                           pocsuite_available=runner.is_available(),
                           stats=_dependency_stats(),
                           poc_sync=sync.last_sync(current_app.config["POC_SYNC_STATE"]),
                           rules_sync=rules_sync.last_sync(current_app.config["RULES_SYNC_STATE"]),
                           proxy_display=settings.proxy_display(values.get("proxy", "")))


def _dependency_stats() -> dict:
    """POC 库里各类外部依赖的数量，用于提示设置生效后会放行多少脚本。"""
    # 只取统计需要的两列：整行实体带着描述与参数 JSON，POC 多时会把设置页拖慢。
    # needs_dnslog 是模型上的 Python property，不能直接写进 query() 的列里。
    rows = (db.session.query(PocRegistry.bruteforce, PocRegistry.oob_kind)
            .filter(PocRegistry.enabled == 1).all())
    return {
        "total": len(rows),
        "bruteforce": sum(1 for row in rows if row.bruteforce),
        "dnslog": sum(1 for row in rows if row.oob_kind in ("dnslog", "both")),
        "search": sum(1 for row in rows if row.oob_kind in ("search", "both")),
        "dnslog_ready": settings.oob_ready(),
    }


def _run_test(kind: str, form):
    ok, message = {
        "proxy": lambda: settings.test_proxy((form.get("test_url") or "").strip(), form=form),
        "oob": lambda: settings.test_oob(form=form),
        "fofa": lambda: settings.test_fofa(form=form),
        "poc_repo": lambda: settings.test_poc_repo(form=form),
        "rules_repo": lambda: settings.test_rules_repo(form=form),
    }.get(kind, lambda: (False, "未知的自测项"))()
    flash(("自测通过：" if ok else "自测未通过：") + message, "success" if ok else "warning")
    return redirect(url_for("settings.index"))
