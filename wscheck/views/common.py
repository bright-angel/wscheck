from __future__ import annotations

from flask import abort, request

from ..extensions import db
from ..models import PocRegistry, ScanFinding, Severity
from ..util import int_value

PAGE_SIZES = (10, 20, 30, 50, 100)

# severity 存的是文本，按 LABELS 顺序排成 CASE 权重，否则字典序会把 critical 排在 info 之后
SEVERITY_RANK = db.case(*[(ScanFinding.severity == value, rank)
                          for rank, value in enumerate(Severity.ORDER)],
                        else_=len(Severity.ORDER))


def paginate(query, default_per_page: int = 20):
    page = int_value(request.args.get("page"), 1, 1)
    requested = int_value(request.args.get("per_page"), default_per_page, 1)
    # 每页条数只接受白名单内的值，任意输入会被吸附到最接近的档位
    per_page = min(PAGE_SIZES, key=lambda size: abs(size - requested))
    return query.paginate(page=page, per_page=per_page, error_out=False)


def int_arg(name: str) -> int | None:
    """读取整数型查询参数，非法或缺失返回 None（筛选条件视为不限）。"""
    raw = (request.args.get(name) or "").strip()
    return int_value(raw) if raw else None


def get_or_404(model, key, label: str = ""):
    row = db.session.get(model, key)
    if row is None:
        abort(404, f"{label or model.__name__}不存在: {key}")
    return row


def poc_capabilities(poc_ids) -> dict:
    """按 poc_id 汇总交互能力，结果行据此决定展示哪种交互控件。"""
    rows = PocRegistry.query.filter(PocRegistry.poc_id.in_(list(poc_ids))).all()
    return {row.poc_id: row.capabilities for row in rows}
