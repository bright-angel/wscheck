"""指纹求值：布尔结果 + 权重得分双输出，并对规则 AST 做进程内缓存。"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field

from . import grammar
from .naming import canonical_app, split_app_names


def normalize(signals: dict[str, str]) -> dict[str, str]:
    """信号按目标统一转小写，避免每条件重复处理大文本。"""
    return {key: str(value or "").lower().strip() for key, value in signals.items()}


@dataclass(slots=True)
class ConditionHit:
    field: str
    op: str
    value: str
    hit: bool
    weight: int
    actual: str

    def to_dict(self) -> dict:
        return {
            "expr": f'{self.field} {self.op} "{self.value}"',
            "hit": self.hit,
            "weight": self.weight if self.hit else 0,
            "actual": self.actual[:120],
        }


@dataclass(slots=True)
class EvalResult:
    matched: bool
    score: int
    threshold: int
    conditions: list[ConditionHit] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "matched": self.matched,
            "score": self.score,
            "threshold": self.threshold,
            "conditions": [c.to_dict() for c in self.conditions],
            "error": self.error,
        }


@dataclass(slots=True)
class CompiledRule:
    """规则的纯数据快照。

    扫描线程池里的求值不能持有 ORM 实例：主线程每次提交进度/日志都会 expire 实例，
    工作线程再访问 rule.enabled 就会触发懒加载，而线程里没有 Flask 应用上下文。
    """

    id: str
    name: str
    expr: str
    threshold: int
    enabled: bool
    app_name: str


class FingerprintEngine:
    def __init__(self, rules, weights: dict):
        self.weights = weights
        self.rules: list[CompiledRule] = []
        self._asts: dict[str, tuple] = {}
        self._errors: dict[str, str] = {}
        self._labels: dict[str, str] = {}
        self._app_labels: dict[str, str] = {}
        self._literals: dict[tuple, tuple] = {}
        self._app_rules: list[CompiledRule] = []
        for source in rules:
            rule = CompiledRule(
                id=str(source.id),
                name=str(getattr(source, "name", "") or ""),
                expr=str(getattr(source, "expr", "") or ""),
                threshold=int(getattr(source, "threshold", 0) or 0),
                enabled=bool(getattr(source, "enabled", True)),
                app_name=str(getattr(source, "app_name", "") or ""),
            )
            self.rules.append(rule)
            self._labels[rule.id] = rule.app_name or rule.name or rule.id
            self._app_labels[rule.id] = rule.app_name
            try:
                ast = grammar.parse(rule.expr)
            except grammar.ParseError as error:
                self._errors[rule.id] = str(error)
                continue
            self._asts[rule.id] = ast
            if any(cond[1] in ("app", "product") for cond in grammar.conditions(ast)):
                self._app_rules.append(rule)

    @property
    def errors(self) -> dict[str, str]:
        return dict(self._errors)

    def label(self, rule_id: str) -> str:
        """规则展示名：APP_NAME 优先，其次名称。"""
        return self._labels.get(rule_id, rule_id)

    def evaluate(self, rule, signals: dict[str, str]) -> EvalResult:
        return self._evaluate_ast(rule, normalize(signals))

    def match(self, signals: dict[str, str]) -> dict[str, EvalResult]:
        """返回命中的规则 -> 结果。"""
        return self._match(normalize(signals))

    def _match(self, signals: dict[str, str], rules=None) -> dict[str, EvalResult]:
        hits = {}
        for rule in self.rules if rules is None else rules:
            if not rule.enabled:
                continue
            result = self._evaluate_ast(rule, signals)
            if result.matched:
                hits[rule.id] = result
        return hits

    def identify(self, signals: dict[str, str]):
        """两遍求值：第一遍按响应信号，第二遍只用 app/product 组合规则补全。"""
        prepared = normalize(signals)
        hits = self._match(prepared)
        app_names = self._names_of(hits)
        if app_names and self._app_rules:
            joined = " ".join(app_names).lower()
            extra = self._match(dict(prepared, app=joined, product=joined), self._app_rules)
            missing = {rid: result for rid, result in extra.items() if rid not in hits}
            if missing:
                hits.update(missing)
                app_names = self._names_of(hits)
        return hits, app_names

    def _names_of(self, hits: dict[str, EvalResult]) -> list[str]:
        # 规则的 app_name 可以是 "GitLab,Jenkins"：拆开后再作为资产应用名，
        # 否则 POC 按单个应用名匹配时整串永远对不上。没有 app_name 的规则
        # 仍退回展示名，但不能按逗号拆规则标题
        names: dict[str, str] = {}
        for rule_id in hits:
            parts = split_app_names(self._app_labels.get(rule_id))
            if not parts:
                label = self._labels.get(rule_id)
                parts = [label] if label else []
            for part in parts:
                key = canonical_app(part)
                if key:
                    names.setdefault(key, part)
        return sorted(names.values())

    def _evaluate_ast(self, rule, signals: dict[str, str]) -> EvalResult:
        ast = self._asts.get(rule.id)
        if ast is None:
            return EvalResult(False, 0, rule.threshold, error=self._errors.get(rule.id, "表达式未解析"))
        passed, score, hits = self._eval(ast, signals)
        return EvalResult(passed and score >= rule.threshold, score, rule.threshold, hits)

    def _eval(self, node: tuple, signals: dict[str, str]):
        kind = node[0]
        if kind == "cond":
            actual = signals.get(node[1], "")
            op, expected, pattern = self._literal(node)
            hit = _compare(actual, op, expected, pattern)
            weight = self.weights.get(node[1], 10) if hit else 0
            return hit, weight, [ConditionHit(node[1], op, node[3], hit, weight, actual)]

        if kind == "not":
            passed, score, hits = self._eval(node[1], signals)
            return not passed, 0, hits

        _, left, right = node
        left_ok, left_score, left_hits = self._eval(left, signals)
        right_ok, right_score, right_hits = self._eval(right, signals)
        hits = left_hits + right_hits
        if kind == "and":
            return left_ok and right_ok, left_score + right_score, hits
        return left_ok or right_ok, left_score + right_score, hits

    def _literal(self, node: tuple) -> tuple:
        """缓存比较值：小写字面量与预编译正则（信号已统一小写，正则忽略大小写）。"""
        cached = self._literals.get(node)
        if cached is None:
            pattern = None
            if node[2] == "~=":
                try:
                    pattern = re.compile(node[3], re.IGNORECASE)
                except re.error:
                    pattern = None
            cached = (node[2], node[3].lower(), pattern)
            self._literals[node] = cached
        return cached


def _compare(actual: str, op: str, expected: str, pattern) -> bool:
    if op == "=":
        return expected in actual
    if op == "!=":
        # 字段缺失（未采集到该信号）时不参与"不包含"判断，避免空信号造成误命中
        return bool(actual) and expected not in actual
    if op == "~=":
        return pattern is not None and pattern.search(actual) is not None
    return actual == expected.strip()


_cache: FingerprintEngine | None = None
_cache_key: tuple | None = None
_lock = threading.Lock()


def get_engine(rules, weights: dict, key: tuple, force: bool = False) -> FingerprintEngine:
    """按规则版本缓存引擎；规则变更（数量或最新更新时间）后自动重建。"""
    global _cache, _cache_key
    with _lock:
        if not force and _cache is not None and _cache_key == key:
            return _cache
        _cache = FingerprintEngine(rules, weights)
        _cache_key = key
        return _cache


def invalidate() -> None:
    global _cache, _cache_key
    with _lock:
        _cache = None
        _cache_key = None
