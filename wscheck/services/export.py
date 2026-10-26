"""结果治理：导出（JSON / CSV / Markdown / HTML）与多任务报告合并。"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import uuid

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..extensions import db
from ..models import (Report, ReviewStatus, ScanFinding, ScanTask, Severity,
                      TargetAsset, TaskStatus, VerifyStatus)
from ..timeutil import fmt_dt, utcnow
from . import evidence as evidence_fmt

COLUMNS = ["任务", "目标", "POC", "POC 名称", "严重等级", "组件", "校验状态", "复核状态", "发现时间"]
EXTRA_COLUMNS = ["校验说明", "复核说明", "HTTP 交互", "证据摘要"]
ASSET_COLUMNS = ["任务", "目标", "状态码", "标题", "Server", "应用指纹", "组件", "目录命中", "采集情况", "采集时间"]

_TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")
_REPORT_ENV = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(("html", "xml")),
    trim_blocks=True,
    lstrip_blocks=True,
)


def collect(task_ids: list[str], include_false_positive: bool = False) -> list[ScanFinding]:
    query = ScanFinding.query.filter(ScanFinding.task_id.in_(task_ids))
    if not include_false_positive:
        query = query.filter(ScanFinding.review_status != ReviewStatus.FALSE_POSITIVE)
    findings = query.all()
    findings.sort(key=lambda f: (Severity.ORDER.index(f.severity) if f.severity in Severity.ORDER else 9,
                                 f.target_url))
    return findings


def collect_assets(task_ids: list[str]) -> list[TargetAsset]:
    if not task_ids:
        return []
    assets = TargetAsset.query.filter(TargetAsset.task_id.in_(task_ids)).all()
    order = {task_id: index for index, task_id in enumerate(task_ids)}
    assets.sort(key=lambda asset: (order.get(asset.task_id, len(order)), asset.url))
    return assets


def asset_stats(assets: list[TargetAsset]) -> dict:
    return {
        "assets": len(assets),
        "fingerprinted": sum(1 for a in assets if _fingerprints(a.fingerprint)),
        "dir_hits": sum(len(_dir_hits(a.dir_hits)) for a in assets),
        "probe_errors": sum(1 for a in assets if a.probe_error),
    }


def stats(findings: list[ScanFinding]) -> dict:
    by_severity = {level: 0 for level in Severity.ORDER}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "confirmed": sum(1 for f in findings if f.verify_status == "confirmed"),
        "suspected": sum(1 for f in findings if f.verify_status in ("suspected", "false_positive_suspected")),
        "false_positive": sum(1 for f in findings if f.review_status == ReviewStatus.FALSE_POSITIVE),
        "targets": len({f.target_url for f in findings}),
    }


def render(tasks: list[ScanTask], findings: list[ScanFinding], assets: list[TargetAsset],
           fmt: str, title: str, timezone: str) -> tuple:
    return RENDERERS[fmt](tasks, findings, assets, title, timezone)


def save_bundle(app, name: str, task_ids: list[str], formats: list[str], timezone: str) -> Report:
    tasks = ScanTask.query.filter(ScanTask.id.in_(task_ids)).order_by(ScanTask.created_at).all()
    findings = collect(task_ids)
    assets = collect_assets(task_ids)
    # 秒级时间戳不足以防重复提交，同名报告并发生成会互相覆盖文件
    directory = os.path.join(
        app.config["REPORT_DIR"],
        f"{_safe(name)}-{utcnow():%Y%m%d%H%M%S}-{uuid.uuid4().hex[:6]}",
    )
    os.makedirs(directory, exist_ok=True)

    files = {}
    try:
        for fmt in formats:
            filename, _, content = render(tasks, findings, assets, fmt, name, timezone)
            path = os.path.join(directory, filename)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
            files[fmt] = path
    except Exception:
        # 任一格式写失败时清掉半套文件，避免留下无法下载的残缺报告
        for path in files.values():
            try:
                os.remove(path)
            except OSError:
                pass
        try:
            os.rmdir(directory)
        except OSError:
            pass
        raise

    report = Report(name=name, task_ids=task_ids, files=files,
                    finding_count=len(findings), created_at=utcnow())
    db.session.add(report)
    db.session.commit()
    return report


def _task_rows(tasks, findings, timezone) -> list[dict]:
    counts = {}
    for finding in findings:
        counts[finding.task_id] = counts.get(finding.task_id, 0) + 1
    return [{
        "id": task.id,
        "name": task.name,
        "status": task.status,
        "status_label": TaskStatus.LABELS.get(task.status, task.status),
        "targets": task.target_count,
        "findings": counts.get(task.id, 0),
        "created_at": fmt_dt(task.created_at, timezone),
    } for task in tasks]


def _fingerprints(value) -> list[dict]:
    if not isinstance(value, dict):
        return []
    rows = []
    for name, score in value.items():
        try:
            score = int(score)
        except (TypeError, ValueError):
            score = 0
        rows.append({"name": str(name), "score": score})
    rows.sort(key=lambda item: (-item["score"], item["name"]))
    return rows


def _dir_hits(value) -> list[dict]:
    if not isinstance(value, list):
        return []
    hits = []
    for hit in value:
        if not isinstance(hit, dict):
            continue
        status = hit.get("status")
        matched = hit.get("matched")
        hits.append({
            "app": str(hit.get("app") or ""),
            "path": str(hit.get("path") or ""),
            "status": status if isinstance(status, int) else None,
            "title": str(hit.get("title") or ""),
            "matched": [str(item) for item in matched] if isinstance(matched, list) else [],
        })
    return hits


def _asset_row(asset, task_names, timezone) -> dict:
    fingerprints = _fingerprints(asset.fingerprint)
    hits = _dir_hits(asset.dir_hits)
    apps = [str(app) for app in asset.app_names] if isinstance(asset.app_names, list) else []
    return {
        "id": asset.id,
        "task_id": asset.task_id,
        "task_name": task_names.get(asset.task_id, ""),
        "url": asset.url,
        "scheme": asset.scheme,
        "host": asset.host,
        "port": asset.port,
        "status_code": asset.status_code,
        "title": asset.title,
        "server": asset.server,
        "favicon_mmh3": asset.favicon_mmh3,
        "fingerprints": fingerprints,
        "fingerprint_text": ", ".join(f"{item['name']} ({item['score']})" for item in fingerprints),
        "apps": apps,
        "apps_text": ", ".join(apps),
        "dir_hits": hits,
        "dir_text": "; ".join(
            f"{hit['app']} {hit['path']}" + (f" ({hit['status']})" if hit["status"] is not None else "")
            for hit in hits
        ),
        "probe_error": asset.probe_error,
        "created_at": fmt_dt(asset.created_at, timezone),
    }


def _asset_rows(tasks, assets, timezone) -> list[dict]:
    task_names = {task.id: task.name for task in tasks}
    return [_asset_row(asset, task_names, timezone) for asset in assets]


def _asset_json(asset, task_names, timezone) -> dict:
    row = _asset_row(asset, task_names, timezone)
    return {
        key: row[key] for key in (
            "id", "task_id", "task_name", "url", "scheme", "host", "port", "status_code",
            "title", "server", "favicon_mmh3", "fingerprints", "apps", "dir_hits",
            "probe_error", "created_at",
        )
    }


def _finding_json(finding, task_names, timezone) -> dict:
    return {
        "id": finding.id,
        "task_id": finding.task_id,
        "task_name": task_names.get(finding.task_id, ""),
        "target_url": finding.target_url,
        "poc_id": finding.poc_id,
        "poc_name": finding.poc_name,
        "severity": finding.severity,
        "severity_label": Severity.LABELS.get(finding.severity, finding.severity),
        "app_name": finding.app_name,
        "verify_status": finding.verify_status,
        "verify_label": VerifyStatus.LABELS.get(finding.verify_status, finding.verify_status),
        "verify_detail": finding.verify_detail,
        "review_status": finding.review_status,
        "review_label": ReviewStatus.LABELS.get(finding.review_status, finding.review_status),
        "review_note": finding.review_note,
        "source": finding.source,
        "http_exchange_count": len(evidence_fmt.exchanges(finding.evidence)),
        "evidence": finding.evidence,
        "created_at": fmt_dt(finding.created_at, timezone),
    }


def _payload(tasks, findings, assets, title, timezone) -> dict:
    task_names = {task.id: task.name for task in tasks}
    summary = stats(findings)
    return {
        "schema": "wscheck.report/v3",
        "title": title,
        "generated_at": fmt_dt(utcnow(), timezone),
        "timezone": timezone,
        "summary": {**summary, **asset_stats(assets), "tasks": len(tasks)},
        "tasks": _task_rows(tasks, findings, timezone),
        "assets": [_asset_json(a, task_names, timezone) for a in assets],
        "findings": [_finding_json(f, task_names, timezone) for f in findings],
    }


def _render_json(tasks, findings, assets, title, timezone):
    data = _payload(tasks, findings, assets, title, timezone)
    return f"{_safe(title)}.json", "application/json", json.dumps(data, ensure_ascii=False, indent=2)


def _render_csv(tasks, findings, assets, title, timezone):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(COLUMNS + EXTRA_COLUMNS)
    task_names = {task.id: task.name for task in tasks}
    for f in findings:
        writer.writerow([_csv_cell(value) for value in (
            task_names.get(f.task_id, f.task_id), f.target_url, f.poc_id, f.poc_name,
            Severity.LABELS.get(f.severity, f.severity), f.app_name,
            VerifyStatus.LABELS.get(f.verify_status, f.verify_status),
            ReviewStatus.LABELS.get(f.review_status, f.review_status),
            fmt_dt(f.created_at, timezone),
            (f.verify_detail or "")[:300], (f.review_note or "")[:300],
            len(evidence_fmt.exchanges(f.evidence)),
            evidence_fmt.summary(f.evidence)[:500],
        )])

    if assets:
        # 结果与资产字段差异太大，同表会多出一半空列，改为第二个带标题的区块
        writer.writerow([])
        writer.writerow(["指纹识别结果"])
        writer.writerow(ASSET_COLUMNS)
        for asset in _asset_rows(tasks, assets, timezone):
            writer.writerow([_csv_cell(value) for value in (
                asset["task_name"], asset["url"], asset["status_code"] or "",
                asset["title"], asset["server"], asset["fingerprint_text"],
                asset["apps_text"], asset["dir_text"],
                asset["probe_error"] or "正常", asset["created_at"],
            )])
    return f"{_safe(title)}.csv", "text/csv", "\ufeff" + buffer.getvalue()


def _csv_cell(value):
    """目标可控的文本以 = + - @ 开头时会被 Excel 当公式执行，导出前加单引号转义。"""
    if not isinstance(value, str):
        return value
    return "'" + value if value.startswith(("=", "+", "-", "@", "\t", "\r")) else value


def _render_markdown(tasks, findings, assets, title, timezone):
    summary = stats(findings)
    asset_summary = asset_stats(assets)
    total = summary["total"] or 1
    generated = fmt_dt(utcnow(), timezone)
    task_names = {task.id: task.name for task in tasks}
    lines = [
        f"# {title}",
        "",
        f"> WSCHECK 安全检测报告 · 生成时间 {generated} · 时区 {timezone}",
        f"> 任务 {len(tasks)} 个 · 结果 {summary['total']} 条 · 涉及目标 {summary['targets']} 个",
        "",
        "## 概览",
        "",
        "| 指标 | 数量 |",
        "| --- | ---: |",
        f"| 结果总数 | {summary['total']} |",
        f"| 已确认 | {summary['confirmed']} |",
        f"| 疑似 | {summary['suspected']} |",
        f"| 涉及目标 | {summary['targets']} |",
        "",
        "### 严重等级分布",
        "",
        "| 严重等级 | 数量 | 占比 |",
        "| --- | ---: | ---: |",
    ]
    for level in Severity.ORDER:
        count = summary["by_severity"].get(level, 0)
        lines.append(f"| {Severity.LABELS[level]} | {count} | {count * 100 / total:.1f}% |")

    lines += ["", "## 任务", "",
              "| 任务 | 状态 | 目标数 | 结果数 | 创建时间 |",
              "| --- | --- | ---: | ---: | --- |"]
    for task in _task_rows(tasks, findings, timezone):
        lines.append(f"| {_md_cell(task['name'])} | {task['status_label']} | {task['targets']} | "
                     f"{task['findings']} | {task['created_at']} |")

    lines += [
        "", "## 指纹识别", "",
        f"> 资产 {asset_summary['assets']} 个 · 识别到指纹 {asset_summary['fingerprinted']} 个 · "
        f"目录命中 {asset_summary['dir_hits']} 条 · 采集异常 {asset_summary['probe_errors']} 个",
        "",
    ]
    if assets:
        lines += [
            "| 任务 | 目标 | 状态码 | 标题 | 应用指纹 | 组件 | 目录命中 | Server | 采集情况 |",
            "| --- | --- | ---: | --- | --- | --- | --- | --- | --- |",
        ]
        for asset in _asset_rows(tasks, assets, timezone):
            lines.append(
                f"| {_md_cell(asset['task_name'])} | {_md_cell(asset['url'])} | "
                f"{asset['status_code'] or '-'} | {_md_cell(asset['title']) or '-'} | "
                f"{_md_cell(asset['fingerprint_text']) or '-'} | {_md_cell(asset['apps_text']) or '-'} | "
                f"{_md_cell(asset['dir_text']) or '-'} | {_md_cell(asset['server']) or '-'} | "
                f"{_md_cell(asset['probe_error']) or '正常'} |"
            )
    else:
        lines.append("（没有采集到指纹识别结果）")

    lines += ["", "## 结果", ""]
    for index, f in enumerate(findings, 1):
        packets = evidence_fmt.packets(f.evidence)
        lines += [
            f"### {index}. [{Severity.LABELS.get(f.severity, f.severity)}] "
            f"{_md_cell(f.poc_name or f.poc_id)}",
            "",
            "| 项目 | 内容 |",
            "| --- | --- |",
            f"| 目标 | {_md_cell(f.target_url)} |",
            f"| 组件 | {_md_cell(f.app_name) or '-'} |",
            f"| 校验 | {VerifyStatus.LABELS.get(f.verify_status, f.verify_status)} |",
            f"| 复核 | {ReviewStatus.LABELS.get(f.review_status, f.review_status)} |",
            f"| POC | {_md_cell(f.poc_id)} |",
            f"| 任务 | {_md_cell(task_names.get(f.task_id, ''))} |",
            f"| 发现时间 | {fmt_dt(f.created_at, timezone)} |",
            "",
        ]
        if f.verify_detail:
            lines += [f"> 校验说明：{_md_cell(f.verify_detail, 500)}", ""]
        if f.review_note:
            lines += [f"> 复核说明：{_md_cell(f.review_note, 500)}", ""]

        if packets:
            lines += [f"**HTTP 交互：{len(packets)} 次**", ""]
            for packet in packets:
                lines += [
                    f"**{packet['index']}/{packet['total']} · {packet['method']} {packet['url']} "
                    f"→ {packet['status_line']}**（{packet['elapsed_ms']} ms）",
                    "",
                    "````http",
                    packet["request"],
                    "",
                    packet["response"],
                    "````",
                    "",
                ]
        else:
            lines += [
                "**HTTP 交互：无**（旧记录，或 POC 使用了非 requests 的请求方式）",
                "",
                f"- 证据摘要：{_md_cell(evidence_fmt.summary(f.evidence))}",
                "",
            ]

        lines += ["**POC 判定输出**", "", "````json",
                  evidence_fmt.detail_json(f.evidence), "````", ""]

    return f"{_safe(title)}.md", "text/markdown", "\n".join(lines)


def _render_html(tasks, findings, assets, title, timezone):
    task_names = {task.id: task.name for task in tasks}
    summary = stats(findings)
    asset_summary = asset_stats(assets)
    total = summary["total"] or 1
    severity_filters = [{
        "key": level,
        "label": Severity.LABELS[level],
        "count": summary["by_severity"].get(level, 0),
        "pct": round(summary["by_severity"].get(level, 0) * 100 / total, 2),
    } for level in Severity.ORDER]

    rows = []
    for f in findings:
        packets = evidence_fmt.packets(f.evidence)
        rows.append({
            "id": f.id,
            "task_name": task_names.get(f.task_id, ""),
            "target_url": f.target_url,
            "poc_id": f.poc_id,
            "poc_name": f.poc_name or f.poc_id,
            "severity": f.severity,
            "severity_label": Severity.LABELS.get(f.severity, f.severity),
            "app_name": f.app_name,
            "verify_label": VerifyStatus.LABELS.get(f.verify_status, f.verify_status),
            "verify_detail": f.verify_detail,
            "review_label": ReviewStatus.LABELS.get(f.review_status, f.review_status),
            "review_note": f.review_note,
            "created_at": fmt_dt(f.created_at, timezone),
            "packets": packets,
            "http_count": len(packets),
            "evidence_summary": evidence_fmt.summary(f.evidence),
            "evidence_detail": evidence_fmt.detail_json(f.evidence),
            "search_blob": " ".join(filter(None, (
                f.target_url, f.poc_name, f.poc_id, f.app_name, task_names.get(f.task_id, ""),
            ))).lower(),
        })

    html = _REPORT_ENV.get_template("reports/export.html").render(
        title=title,
        generated_at=fmt_dt(utcnow(), timezone),
        timezone=timezone,
        summary=summary,
        asset_summary=asset_summary,
        severity_filters=severity_filters,
        tasks=_task_rows(tasks, findings, timezone),
        assets=_asset_rows(tasks, assets, timezone),
        findings=rows,
    )
    return f"{_safe(title)}.html", "text/html", html


def _md_cell(value, limit: int = 300) -> str:
    text = str(value or "").replace("|", "\\|").replace("\n", " ").strip()
    return text if len(text) <= limit else text[:limit] + "…"


def _safe(name: str) -> str:
    cleaned = re.sub(r"[^\w\u4e00-\u9fa5.\-]+", "-", (name or "").strip()).strip("-.")
    return cleaned[:60] or "report"


FORMATS = {"html": "HTML", "md": "Markdown", "json": "JSON", "csv": "CSV"}
RENDERERS = {"json": _render_json, "csv": _render_csv, "md": _render_markdown, "html": _render_html}
