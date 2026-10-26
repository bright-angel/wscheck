"""指纹规则仓库同步：拉取 YAML 规则文件到 rules/ 并导入数据库。

文件镜像复用 services/repo_sync.py；导入时按规则 ID 覆盖仓库提供的字段，保留页面上手工设置的
启用/停用状态。上次同步提供、本次仓库和本地其他规则文件都不再包含的 ID 会从数据库删除，
手工新建的规则不受影响。
"""

from __future__ import annotations

import os
from pathlib import PurePosixPath

import yaml
from sqlalchemy.exc import SQLAlchemyError

from ...extensions import db
from ...models import FingerprintRule
from ...timeutil import utcnow
from .. import repo_sync, settings
from ..repo_sync import SyncError

RULE_SUFFIXES = (".yaml", ".yml")


def config_from_settings() -> repo_sync.RepositoryConfig:
    return repo_sync.RepositoryConfig(
        repo_url=settings.get("rules_repo_url"),
        ref=settings.get("rules_repo_ref"),
        subdir=settings.get("rules_repo_subdir"),
        token=settings.get("rules_github_token"),
    )


def sync_rules(cfg: repo_sync.RepositoryConfig, rules_dir: str, state_path: str,
               backup_root: str, proxies: dict | None = None,
               force: bool = False) -> tuple[repo_sync.SyncResult, dict]:
    """同步仓库中的规则文件并导入数据库，返回 (同步结果, 导入统计)。"""
    previous = set(repo_sync.load_manifest(state_path).get("rule_ids") or [])
    result = repo_sync.sync_from_repo(
        cfg, rules_dir, state_path, backup_root, proxies=proxies, force=force,
        validator=_validate_rule_files, label="指纹规则",
    )
    if result.unchanged:
        return result, _empty_stats()
    names = repo_sync.load_manifest(state_path).get("files") or []
    stats = _import_rules(rules_dir, names, previous)
    repo_sync.patch_manifest(state_path, rule_ids=stats.pop("ids"))
    return result, stats


def last_sync(path: str) -> dict:
    return repo_sync.last_sync(path)


def _import_rules(directory: str, names: list[str], stale_ids: set[str]) -> dict:
    rules: dict[str, dict] = {}
    invalid = 0
    for rel in names:
        if not _is_rule_file(rel):
            continue
        path = _join(directory, rel)
        if path is None:
            invalid += 1
            continue
        items, bad = _load_rules(path)
        invalid += bad
        for rule in items:
            rules[rule["id"]] = rule

    existing = {}
    if rules:
        existing = {row.id: row for row in
                    FingerprintRule.query.filter(FingerprintRule.id.in_(list(rules))).all()}
    added = updated = 0
    now = utcnow()
    for rule_id, rule in rules.items():
        row = existing.get(rule_id)
        if row is None:
            db.session.add(FingerprintRule(
                id=rule_id, name=rule["name"], expr=rule["expr"],
                threshold=rule["threshold"], app_name=rule["app_name"],
                note=rule["note"], enabled=rule["enabled"],
                created_at=now, updated_at=now,
            ))
            added += 1
            continue
        if (row.name != rule["name"] or row.expr != rule["expr"]
                or row.threshold != rule["threshold"] or row.app_name != rule["app_name"]
                or (row.note or "") != rule["note"]):
            row.name = rule["name"]
            row.expr = rule["expr"]
            row.threshold = rule["threshold"]
            row.app_name = rule["app_name"]
            row.note = rule["note"]
            row.updated_at = now
            updated += 1

    # 其他本地规则文件（内置或手工放置）仍在定义同名 ID 时不能删除
    present = set(rules) | _all_rule_ids(directory)
    removed = 0
    for rule_id in sorted(set(stale_ids) - present):
        row = db.session.get(FingerprintRule, rule_id)
        if row is not None:
            db.session.delete(row)
            removed += 1
    try:
        db.session.commit()
    except SQLAlchemyError as error:
        db.session.rollback()
        raise repo_sync.SyncError(f"规则文件已同步，但导入数据库失败：{error}") from error

    return {"added": added, "updated": updated, "removed": removed,
            "invalid": invalid, "total": len(rules), "ids": sorted(rules)}


def _validate_rule_files(files: dict[str, str]) -> None:
    names = [rel for rel in files if _is_rule_file(rel)]
    if not names:
        raise repo_sync.SyncError("仓库（子目录）里没有 YAML 指纹规则文件")
    for rel in names:
        items, _ = _load_rules(files[rel])
        if items:
            return
    raise repo_sync.SyncError("仓库（子目录）里没有可导入的指纹规则（需要包含 id 与 expr 的 YAML 列表）")


def _empty_stats() -> dict:
    return {"added": 0, "updated": 0, "removed": 0, "invalid": 0, "total": 0}


def _is_rule_file(rel: str) -> bool:
    return rel.lower().endswith(RULE_SUFFIXES)


def _join(directory: str, rel: str) -> str | None:
    parts = PurePosixPath(rel).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        return None
    return os.path.join(directory, *parts)


def _load_rules(path: str) -> tuple[list[dict], int]:
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or []
    except (OSError, yaml.YAMLError):
        return [], 1
    if not isinstance(data, list):
        return [], 1
    rules: list[dict] = []
    invalid = 0
    for item in data:
        rule = _coerce_rule(item)
        if rule is None:
            invalid += 1
        else:
            rules.append(rule)
    return rules, invalid


def _coerce_rule(item) -> dict | None:
    if not isinstance(item, dict):
        return None
    rule_id = str(item.get("id") or "").strip()
    expr = str(item.get("expr") or "").strip()
    if not rule_id or not expr:
        return None
    return {
        "id": rule_id,
        "name": str(item.get("name") or rule_id),
        "expr": expr,
        "threshold": _threshold(item.get("threshold")),
        "app_name": str(item.get("app_name") or ""),
        "note": str(item.get("note") or ""),
        "enabled": 1 if item.get("enabled", True) else 0,
    }


def _threshold(value) -> int:
    try:
        return int(value if value is not None else 30)
    except (TypeError, ValueError):
        return 30


def _all_rule_ids(directory: str) -> set[str]:
    ids: set[str] = set()
    for root, dirs, names in os.walk(directory):
        dirs[:] = [name for name in dirs if not name.startswith(".")]
        for name in names:
            if not name.lower().endswith(RULE_SUFFIXES):
                continue
            items, _ = _load_rules(os.path.join(root, name))
            ids.update(rule["id"] for rule in items)
    return ids
