"""启动准备：补齐表结构、内置指纹规则入库、POC 目录建索引、中断任务恢复。"""

from __future__ import annotations

import glob
import json
import os

import yaml
from sqlalchemy import inspect, text

from ..extensions import db
from ..models import FingerprintRule
from ..timeutil import utcnow
from . import taskmgr
from .poc import indexer

# create_all 只会建新表，不会给已有表加列，这里按模型声明补齐
POC_REGISTRY_COLUMNS = {
    "vul_id": "VARCHAR(64) DEFAULT ''",
    "vul_type": "VARCHAR(64) DEFAULT ''",
    "supports_attack": "INTEGER DEFAULT 0",
    "supports_shell": "INTEGER DEFAULT 0",
    "needs_oob": "INTEGER DEFAULT 0",
    "oob_kind": "VARCHAR(16) DEFAULT ''",
    "bruteforce": "INTEGER DEFAULT 0",
    "loadable": "INTEGER DEFAULT 1",
    "load_error": "VARCHAR(255) DEFAULT ''",
    "poc_refs": "JSON",
    "poc_options": "JSON",
}
TARGET_ASSET_COLUMNS = {
    "dir_hits": "JSON",
}


def prepare_storage(app) -> None:
    upgraded = _upgrade_columns("poc_registry", POC_REGISTRY_COLUMNS)
    upgraded += _upgrade_columns("target_assets", TARGET_ASSET_COLUMNS)
    seeded = _seed_fingerprints(app)
    rules_synced = _auto_sync_rules(app)
    synced = _auto_sync_pocs(app)
    indexed = indexer.sync_registry(app.config["POC_DIR"], db.session)
    recovered = taskmgr.recover_interrupted()
    app.logger.info(
        "初始化完成：表补列 %d，指纹规则新增 %d，规则仓库同步 %s，POC 仓库同步 %s，"
        "POC 索引 %d/%d，中断任务恢复 %d",
        upgraded, seeded, rules_synced, synced, indexed["added"], indexed["total"], recovered,
    )


def _auto_sync_rules(app) -> str:
    """启动时按设置拉取指纹规则仓库；失败只记警告，继续用本地规则。"""
    from . import settings

    if not settings.get("rules_auto_sync") or not settings.get("rules_repo_url"):
        return "未启用"
    from .fingerprint import invalidate
    from .fingerprint import sync as rules_sync

    try:
        result, stats = rules_sync.sync_rules(
            rules_sync.config_from_settings(), app.config["RULES_DIR"],
            app.config["RULES_SYNC_STATE"], app.config["RULES_SYNC_BACKUP_DIR"],
            proxies=settings.http_proxies(), force=False,
        )
    except (rules_sync.SyncError, OSError) as error:
        app.logger.warning("指纹规则仓库自动同步失败，继续使用本地规则：%s", error)
        return "失败"
    if result.unchanged:
        app.logger.info("指纹规则仓库自动同步：%s@%s 已是最新（%s）",
                        result.slug, result.ref, result.commit[:7])
        return "已是最新"
    invalidate()
    app.logger.info("指纹规则仓库自动同步：%s@%s 提交 %s，写入 %d 个文件，移除 %d 个；"
                    "规则新增 %d 条、更新 %d 条、删除 %d 条",
                    result.slug, result.ref, result.commit[:7], result.written,
                    result.removed, stats["added"], stats["updated"], stats["removed"])
    if stats["invalid"]:
        app.logger.warning("规则仓库中有 %d 条条目缺少 id/expr 或无法解析，已忽略", stats["invalid"])
    return f"新增 {stats['added']} 条规则"


def _auto_sync_pocs(app) -> str:
    """启动时按设置拉取 POC 仓库；失败只记警告，继续用本地已有文件。"""
    from . import settings

    if not settings.get("poc_auto_sync") or not settings.get("poc_repo_url"):
        return "未启用"
    from .poc import sync

    try:
        result = sync.sync_from_repo(
            sync.config_from_settings(), app.config["POC_DIR"],
            app.config["POC_SYNC_STATE"], app.config["POC_SYNC_BACKUP_DIR"],
            proxies=settings.http_proxies(), force=False,
        )
    except (sync.SyncError, OSError) as error:
        app.logger.warning("POC 仓库自动同步失败，继续使用本地文件：%s", error)
        return "失败"
    if result.unchanged:
        app.logger.info("POC 仓库自动同步：%s@%s 已是最新（%s）",
                        result.slug, result.ref, result.commit[:7])
        return "已是最新"
    app.logger.info("POC 仓库自动同步：%s@%s 提交 %s，写入 %d 个文件，移除 %d 个，跳过 %d 个",
                    result.slug, result.ref, result.commit[:7], result.written,
                    result.removed, len(result.skipped))
    if result.skipped:
        app.logger.warning("以下 POC 文件写入时被删除（可能是本机安全软件隔离），"
                           "请把 POC 目录加入信任：%s", "、".join(result.skipped[:10]))
    return f"写入 {result.written} 个文件"


def _upgrade_columns(table: str, columns_ddl: dict[str, str]) -> int:
    inspector = inspect(db.engine)
    if table not in inspector.get_table_names():
        return 0
    columns = {row[1] for row in db.session.execute(text(f"PRAGMA table_info({table})"))}
    added = 0
    for name, ddl in columns_ddl.items():
        if name in columns:
            continue
        db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
        added += 1
    if added:
        db.session.commit()
    return added


def _seed_fingerprints(app) -> int:
    """按文件导入 rules 目录下的 YAML，已导入过的文件不重复写入。"""
    directory = app.config["RULES_DIR"]
    if not os.path.isdir(directory):
        return 0
    state_path = app.config["RULES_SEED_STATE"]
    imported = _load_state(state_path)
    existing = {row[0] for row in db.session.query(FingerprintRule.id)}
    added = skipped = processed = 0

    for path in sorted(glob.glob(os.path.join(directory, "*.y*ml"))):
        filename = os.path.basename(path)
        if filename in imported:
            continue
        try:
            with open(path, encoding="utf-8") as handle:
                rules = yaml.safe_load(handle) or []
        except (OSError, yaml.YAMLError) as error:
            # 单个规则文件损坏不能让整个服务起不来；不记录到 state，下次启动会重试
            app.logger.warning("指纹规则文件读取失败，已跳过 %s: %s", filename, error)
            continue
        if not isinstance(rules, list):
            app.logger.warning("指纹规则文件格式应为 YAML 列表，已跳过 %s", filename)
            continue
        for item in rules:
            if not isinstance(item, dict):
                continue
            rule_id = str(item.get("id") or "").strip()
            if not rule_id:
                continue
            if rule_id in existing:
                skipped += 1
                continue
            db.session.add(FingerprintRule(
                id=rule_id,
                name=str(item.get("name") or rule_id),
                expr=str(item.get("expr") or ""),
                threshold=_threshold(item.get("threshold")),
                app_name=str(item.get("app_name") or ""),
                enabled=1 if item.get("enabled", True) else 0,
                note=str(item.get("note") or ""),
                created_at=utcnow(),
                updated_at=utcnow(),
            ))
            existing.add(rule_id)
            added += 1
        imported[filename] = len(rules)
        processed += 1
        db.session.commit()

    if processed:
        _save_state(state_path, imported)
    if skipped:
        app.logger.info("指纹规则导入：跳过 %d 条库中已存在的 id", skipped)
    return added


def _threshold(value) -> int:
    """阈值来自外部 YAML，类型写错时退回默认值，不能让它中断启动流程。"""
    try:
        return int(value if value is not None else 30)
    except (TypeError, ValueError):
        return 30


def _load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(path: str, imported: dict) -> None:
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(imported, handle, ensure_ascii=False, indent=2)
    except OSError:
        pass
