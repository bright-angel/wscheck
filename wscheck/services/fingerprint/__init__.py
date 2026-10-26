from __future__ import annotations

from flask import current_app

from ...extensions import db
from ...models import FingerprintRule
from .engine import EvalResult, FingerprintEngine, get_engine, invalidate
from .grammar import ParseError, describe, parse
from .naming import app_keys, canonical_app, related_app, related_keys, split_app_names
from .signals import ProbeResult, probe

__all__ = [
    "EvalResult", "FingerprintEngine", "ProbeResult", "ParseError", "app_rule_counts",
    "app_keys", "canonical_app", "describe", "engine_for", "engine_from_db", "invalidate",
    "parse", "probe", "related_app", "split_app_names",
]


def app_rule_counts(names) -> dict[str, int]:
    """应用名 → 关联的启用指纹规则数，供 POC 库标注组件是否有对应指纹。"""
    wanted = [(name, app_keys(name)) for name in names if name]
    if not wanted:
        return {}
    rule_keys = []
    for (rule_app,) in db.session.query(FingerprintRule.app_name).filter(FingerprintRule.enabled == 1):
        keys = app_keys(rule_app)
        if keys:
            rule_keys.append(keys)
    return {
        name: sum(1 for keys in rule_keys
                  if any(related_keys(left, right) for left in wanted_keys for right in keys))
        for name, wanted_keys in wanted
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
