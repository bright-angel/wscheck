"""WSCHECK - Web 安全检测工具（授权测试用途）。"""

from __future__ import annotations

import logging
import os
from urllib.parse import urlsplit

from flask import Flask, abort, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from .extensions import db
from . import timeutil

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def create_app(config_object: str = "config.Config") -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    for path in (os.path.join(app.root_path, "..", "data"),
                 app.config["REPORT_DIR"], app.config["EXPORT_DIR"]):
        os.makedirs(os.path.abspath(path), exist_ok=True)

    db.init_app(app)
    timeutil.init_app(app)
    _register_blueprints(app)
    _register_jinja_helpers(app)
    _register_error_pages(app)
    _register_same_origin_guard(app)

    from .services.bootstrap import prepare_storage

    with app.app_context():
        db.create_all()
        prepare_storage(app)
    return app


def _register_blueprints(app: Flask) -> None:
    from .views import (actions, findings, fingerprints, main, pocs, reports,
                        settings, tasks)

    for module, name in ((main, "main"), (tasks, "tasks"), (fingerprints, "fingerprints"),
                         (pocs, "pocs"), (findings, "findings"), (actions, "actions"),
                         (reports, "reports"), (settings, "settings")):
        app.register_blueprint(module.bp, name=name)


def _register_jinja_helpers(app: Flask) -> None:
    import json

    from .models import ReviewStatus, Severity, TaskStatus, VerifyStatus
    from .services import evidence as evidence_fmt
    from .views.common import PAGE_SIZES

    app.jinja_env.globals.update(
        TaskStatus=TaskStatus,
        Severity=Severity,
        ReviewStatus=ReviewStatus,
        VerifyStatus=VerifyStatus,
        PAGE_SIZES=PAGE_SIZES,
    )
    app.jinja_env.filters["app_names"] = lambda names: "、".join(names) if names else "-"
    app.jinja_env.filters["tojsonindent"] = lambda value: json.dumps(
        value, ensure_ascii=False, indent=2, default=str
    )
    app.jinja_env.filters["http_packets"] = evidence_fmt.packets
    app.jinja_env.filters["evidence_detail"] = evidence_fmt.detail_json
    app.jinja_env.filters["evidence_error"] = evidence_fmt.error_text


def _register_error_pages(app: Flask) -> None:
    generic = {400: "请求参数有误", 403: "没有访问权限", 404: "页面不存在",
               405: "该地址不支持这个请求方法", 409: "请求与当前状态冲突"}

    @app.errorhandler(HTTPException)
    def http_error(error: HTTPException):
        # 没有这个处理器时，abort(400)/405 会被下面的 Exception 兜底吞成 500
        custom = error.description != type(error).description
        message = error.description if custom else generic.get(error.code, error.description)
        if _wants_json():
            return jsonify(error=message), error.code
        return render_template("error.html", code=error.code, message=message), error.code

    @app.errorhandler(Exception)
    def server_error(error):
        app.logger.exception("未处理异常: %s", error)
        # 异常文本可能带 SQL、表名或绝对路径，只留在服务端日志里
        message = "服务内部错误，请查看服务端日志"
        if _wants_json():
            return jsonify(error=message), 500
        return render_template("error.html", code=500, message=message), 500


def _register_same_origin_guard(app: Flask) -> None:
    """写操作只接受同源请求，挡住跨站表单自动提交（不依赖前端 CSRF token）。"""

    @app.before_request
    def _same_origin_only():
        if request.method not in UNSAFE_METHODS:
            return None
        if request.headers.get("Sec-Fetch-Site", "").lower() == "cross-site":
            abort(403, "跨站请求被拒绝")
        origin = request.headers.get("Origin")
        if origin is not None:
            if _netloc_of(origin) != request.host.lower():
                abort(403, "跨站请求被拒绝")
            return None
        referer = request.headers.get("Referer")
        if referer and _netloc_of(referer) != request.host.lower():
            abort(403, "跨站请求被拒绝")
        return None


def _netloc_of(value: str) -> str:
    return urlsplit(value).netloc.lower()


def _wants_json() -> bool:
    return request.headers.get("Accept", "").split(",")[0].strip() == "application/json"
