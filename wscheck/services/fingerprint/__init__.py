from __future__ import annotations

import re

from flask import current_app

from ...extensions import db
from ...models import FingerprintRule
from .engine import EvalResult, FingerprintEngine, get_engine, invalidate
from .grammar import ParseError, describe, parse
from .signals import ProbeResult, probe

__all__ = [
    "EvalResult", "FingerprintEngine", "ProbeResult", "ParseError", "app_rule_counts",
    "canonical_app", "describe", "engine_for", "engine_from_db", "invalidate", "parse",
    "probe", "related_app",
]


def canonical_app(name: str) -> str:
    return re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", (name or "").lower())


def _related_keys(left: str, right: str) -> bool:
    if not left or not right:
        return False
    if left == right:
        return True
    return len(left) >= 4 and len(right) >= 4 and (left in right or right in left)


def related_app(left: str, right: str) -> bool:
    """两个应用名是否指同一产品（容忍厂商前缀、空格与连字符差异）。"""
    return _related_keys(canonical_app(left), canonical_app(right))


def app_rule_counts(names) -> dict[str, int]:
    """应用名 → 关联的启用指纹规则数，供 POC 库标注组件是否有对应指纹。"""
    wanted = {name: canonical_app(name) for name in names if name}
    if not wanted:
        return {}
    rule_keys: dict[str, int] = {}
    for (rule_app,) in db.session.query(FingerprintRule.app_name).filter(FingerprintRule.enabled == 1):
        key = canonical_app(rule_app)
        if key:
            rule_keys[key] = rule_keys.get(key, 0) + 1
    return {
        name: sum(count for key, count in rule_keys.items() if _related_keys(canon, key))
        for name, canon in wanted.items()
    }


def engine_from_db() -> FingerprintEngine:
    """加载启用中的规则并复用进程内 AST 缓存。"""
    rules = FingerprintRule.query.filter_by(enabled=1).order_by(FingerprintRule.id).all()
    version = (len(rules), max((r.updated_at for r in rules), default=None))
    return get_engine(rules, current_app.config["SIGNAL_WEIGHTS"], version)


def engine_for(rule_ids) -> FingerprintEngine:
    """任务限定部分规则时按 id 过滤；未限定时复用全量引擎缓存，避免重复解析上千条 AST。"""
    if not rule_ids:
        return engine_from_db()
    rules = FingerprintRule.query.filter(FingerprintRule.enabled == 1).all()
    wanted = set(rule_ids)
    selected = [r for r in rules if r.id in wanted]
    return FingerprintEngine(selected, current_app.config["SIGNAL_WEIGHTS"])
