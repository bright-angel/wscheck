"""数据模型：与设计文档 §4 对齐，SQLite + SQLAlchemy 2.0 声明式。"""

from __future__ import annotations

import re
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .extensions import db
from .timeutil import utcnow

# 命令控制台只接受真正的命令参数；payload/code 一类多为上传或注入载荷，不列入
COMMAND_OPTION_RE = re.compile(r"(cmd|command|exec)", re.IGNORECASE)


class TaskStatus:
    PENDING = "pending"
    RUNNING = "running"
    CANCELING = "canceling"
    DONE = "done"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELED = "canceled"

    LABELS = {
        PENDING: "排队中",
        RUNNING: "运行中",
        CANCELING: "取消中",
        DONE: "已完成",
        PARTIAL: "部分完成",
        FAILED: "失败",
        CANCELED: "已取消",
    }
    BADGES = {
        PENDING: "secondary",
        RUNNING: "primary",
        CANCELING: "warning",
        DONE: "success",
        PARTIAL: "info",
        FAILED: "danger",
        CANCELED: "dark",
    }
    ACTIVE = (PENDING, RUNNING, CANCELING)


class Severity:
    LABELS = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "信息",
    }
    ORDER = ("critical", "high", "medium", "low", "info")
    BADGES = {
        "critical": "danger",
        "high": "danger",
        "medium": "warning",
        "low": "info",
        "info": "secondary",
    }


class VerifyStatus:
    LABELS = {
        "confirmed": "已确认",
        "suspected": "疑似",
        "false_positive_suspected": "疑似误报",
        "unverified": "未校验",
    }


class ReviewStatus:
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"

    LABELS = {
        PENDING: "待复核",
        CONFIRMED: "确认有效",
        FALSE_POSITIVE: "误报",
    }


# POC 的外部依赖类型：dnslog 类在设置里配好 OOB 域名或 ceye token 就能跑，
# search 类依赖 fofa/shodan 之类搜索引擎拉目标，与本工具"按给定目标扫描"的口径不符
OOB_KIND_LABELS = {
    "dnslog": "依赖 OOB 平台",
    "search": "依赖搜索引擎",
    "both": "依赖 OOB 平台与搜索引擎",
}


class ScanTask(db.Model):
    __tablename__ = "scan_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), default="")
    status: Mapped[str] = mapped_column(String(16), index=True, default=TaskStatus.PENDING)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    input_raw: Mapped[str] = mapped_column(Text, default="")
    target_count: Mapped[int] = mapped_column(Integer, default=0)
    poc_ids: Mapped[list] = mapped_column(JSON, default=list)
    fingerprint_ids: Mapped[list] = mapped_column(JSON, default=list)
    config_json: Mapped[dict] = mapped_column(JSON, default=dict)
    error_message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    assets: Mapped[list["TargetAsset"]] = relationship(
        back_populates="task", cascade="all, delete-orphan", passive_deletes=True
    )
    findings: Mapped[list["ScanFinding"]] = relationship(
        back_populates="task", cascade="all, delete-orphan", passive_deletes=True
    )
    logs: Mapped[list["TaskLog"]] = relationship(
        back_populates="task", cascade="all, delete-orphan", passive_deletes=True, order_by="TaskLog.id"
    )
    actions: Mapped[list["PocAction"]] = relationship(
        back_populates="task", cascade="all, delete-orphan", passive_deletes=True
    )

    @property
    def status_label(self) -> str:
        return TaskStatus.LABELS.get(self.status, self.status)

    @property
    def is_active(self) -> bool:
        return self.status in TaskStatus.ACTIVE


class TargetAsset(db.Model):
    __tablename__ = "target_assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("scan_tasks.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(512))
    scheme: Mapped[str] = mapped_column(String(16), default="")
    host: Mapped[str] = mapped_column(String(255), default="")
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str] = mapped_column(Text, default="")
    server: Mapped[str] = mapped_column(String(255), default="")
    favicon_mmh3: Mapped[str] = mapped_column(String(32), default="")
    fingerprint: Mapped[dict] = mapped_column(JSON, default=dict)
    app_names: Mapped[list] = mapped_column(JSON, default=list)
    dir_hits: Mapped[list] = mapped_column(JSON, default=list)
    probe_error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    task: Mapped[ScanTask] = relationship(back_populates="assets")


class ScanFinding(db.Model):
    __tablename__ = "scan_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("scan_tasks.id", ondelete="CASCADE"), index=True)
    target_url: Mapped[str] = mapped_column(String(512))
    poc_id: Mapped[str] = mapped_column(String(255))
    poc_name: Mapped[str] = mapped_column(String(255), default="")
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True)
    app_name: Mapped[str] = mapped_column(String(120), default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    verify_status: Mapped[str] = mapped_column(String(32), default="unverified")
    verify_detail: Mapped[str] = mapped_column(Text, default="")
    review_status: Mapped[str] = mapped_column(String(24), default=ReviewStatus.PENDING, index=True)
    review_note: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(24), default="scan")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    task: Mapped[ScanTask] = relationship(back_populates="findings")
    actions: Mapped[list["PocAction"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", passive_deletes=True
    )


class PocAction(db.Model):
    """结果行上每次 attack / 命令控制台执行的留痕，兼作控制台的输出历史。"""

    __tablename__ = "poc_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("scan_tasks.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("scan_findings.id", ondelete="CASCADE"), index=True)
    poc_id: Mapped[str] = mapped_column(String(255), default="")
    target_url: Mapped[str] = mapped_column(String(512), default="")
    mode: Mapped[str] = mapped_column(String(16), default="attack")
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="failed")
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    task: Mapped[ScanTask] = relationship(back_populates="actions")
    finding: Mapped[ScanFinding] = relationship(back_populates="actions")


class FingerprintRule(db.Model):
    __tablename__ = "fingerprint_rules"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), default="")
    expr: Mapped[str] = mapped_column(Text, default="")
    threshold: Mapped[int] = mapped_column(Integer, default=30)
    app_name: Mapped[str] = mapped_column(String(120), default="")
    enabled: Mapped[int] = mapped_column(Integer, default=1)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class PocRegistry(db.Model):
    __tablename__ = "poc_registry"

    poc_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    app_name: Mapped[str] = mapped_column(String(120), default="", index=True)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    file_path: Mapped[str] = mapped_column(String(512), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[int] = mapped_column(Integer, default=1)
    vul_id: Mapped[str] = mapped_column(String(64), default="")
    vul_type: Mapped[str] = mapped_column(String(64), default="")
    # 静态探测出的模式支持面：attack 可真实写目标，shell 需要目标回连
    supports_attack: Mapped[int] = mapped_column(Integer, default=0)
    supports_shell: Mapped[int] = mapped_column(Integer, default=0)
    # 耗时/依赖外部条件的 POC：默认不进扫描，否则单个 POC 能把整个任务挂住
    needs_oob: Mapped[int] = mapped_column(Integer, default=0)
    # 外部依赖类型：dnslog（可用设置的 OOB 域名解锁）/ search（依赖搜索引擎，本工具不放行）/ both
    oob_kind: Mapped[str] = mapped_column(String(16), default="")
    bruteforce: Mapped[int] = mapped_column(Integer, default=0)
    # pocsuite3 只加载正文里出现 register_poc / matchers 的脚本，其余文件引擎会直接跳过
    loadable: Mapped[int] = mapped_column(Integer, default=1)
    load_error: Mapped[str] = mapped_column(String(255), default="")
    poc_refs: Mapped[list] = mapped_column(JSON, default=list)
    poc_options: Mapped[list] = mapped_column(JSON, default=list)
    indexed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    @property
    def command_option(self) -> str:
        """可用于命令控制台的参数名，取第一个名字像命令的选项。"""
        for option in self.poc_options or []:
            if COMMAND_OPTION_RE.fullmatch(str(option.get("name", ""))):
                return option["name"]
        return ""

    @property
    def supports_console(self) -> bool:
        """命令控制台要求 POC 既能注入命令，又实现了 attack 模式，否则参数不会被真正使用。"""
        return bool(self.command_option and self.supports_attack)

    @property
    def shell_only(self) -> bool:
        """只有 shell 模式的 POC 需要目标回连监听端口，Web 端不提供交互。"""
        return bool(self.supports_shell and not self.supports_attack)

    @property
    def capabilities(self) -> dict:
        return {"attack": bool(self.supports_attack), "console": self.supports_console,
                "shell_only": self.shell_only}

    @property
    def heavy_reason(self) -> str:
        """不适合进常规扫描的原因：这类 POC 要么打不完，要么要别人家的平台。"""
        if self.bruteforce:
            return "弱口令爆破"
        return OOB_KIND_LABELS.get(self.oob_kind, "")

    @property
    def needs_dnslog(self) -> bool:
        """配置了 OOB 域名或 ceye token 之后就可以放进扫描。"""
        return self.oob_kind in ("dnslog", "both")


class TaskLog(db.Model):
    __tablename__ = "task_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("scan_tasks.id", ondelete="CASCADE"), index=True)
    level: Mapped[str] = mapped_column(String(8), default="info")
    message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    task: Mapped[ScanTask] = relationship(back_populates="logs")


class Report(db.Model):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(160), default="")
    task_ids: Mapped[list] = mapped_column(JSON, default=list)
    files: Mapped[dict] = mapped_column(JSON, default=dict)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Setting(db.Model):
    """全局设置的键值存储：代理、OOB 平台、请求参数等，扫描与交互执行都会读取。"""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
