"""POC 索引：静态解析 pocsuite3 格式 POC 的元数据（不执行 POC 代码）。"""

from __future__ import annotations

import ast
import os
import re
import warnings
from dataclasses import dataclass, field

from ...timeutil import utcnow

# 依赖外部平台才能出结果的 POC：没配置 token 时 pocsuite3 会走 getpass 要输入（后台线程里永久挂住），
# 或反复请求 api.ceye.io / fofa / shodan 直到超时，全量扫描会被这类 POC 拖慢一个数量级
# dnslog 类可以用「设置」里的 OOB 域名 / CEye token 解锁；search 类要靠搜索引擎拉目标，本工具不放行
DNSLOG_SYMBOLS = {"CEye", "httpOOb", "interactsh", "Interactsh", "Dnslog", "DNSLOG", "PHTTPServer"}
SEARCH_SYMBOLS = {"FOFA", "Shodan", "Hunter", "ZoomEye", "Censys", "Quake", "Seebug"}

SEVERITY_BY_VUL_TYPE = {
    "CODE_EXECUTION": "critical",
    "COMMAND_EXECUTION": "critical",
    "REMOTE_CODE_EXECUTION": "critical",
    "RCE": "critical",
    "SQL_INJECTION": "high",
    "WEBSHELL": "critical",
    "BACKDOOR": "critical",
    "UPLOAD_FILES": "critical",
    "ARBITRARY_FILE_READ": "high",
    "ARBITRARY_FILE_DOWNLOAD": "high",
    "ARBITRARY_FILE_CREATION": "critical",
    "PATH_TRAVERSAL": "high",
    "LOCAL_FILE_INCLUSION": "high",
    "REMOTE_FILE_INCLUSION": "high",
    "DIRECTORY_TRAVERSAL": "high",
    "AUTH_BY_PASS": "high",
    "AUTH_BYPASS": "high",
    "LOGIN_BYPASS": "high",
    "UNAUTHORIZED_ACCESS": "high",
    "SECURITY_MODE_BYPASS": "medium",
    "XXE": "high",
    "XML_INJECTION": "high",
    "SSRF": "high",
    "DESERIALIZATION": "critical",
    "XSS": "medium",
    "UXSS": "medium",
    "CSRF": "medium",
    "CRLF_INJECTION": "medium",
    "WEAK_PASSWORD": "medium",
    "INFO_LEAK": "low",
    "INFORMATION_DISCLOSURE": "low",
    "CODE_DISCLOSURE": "low",
    "PATH_DISCLOSURE": "low",
    "DIRECTORY_LISTING": "low",
    "BACKUP_FILE_FOUND": "low",
    "CORS": "low",
    "DEFAULT_CONFIG": "low",
    "USE_OF_THIRD_PARTY": "info",
    "OTHER": "medium",
}

@dataclass(slots=True)
class PocMeta:
    poc_id: str
    file_path: str
    name: str = ""
    app_name: str = ""
    severity: str = "info"
    vul_id: str = ""
    vul_type: str = ""
    description: str = ""
    references: list[str] = field(default_factory=list)
    supports_attack: bool = False
    supports_shell: bool = False
    needs_oob: bool = False
    oob_kind: str = ""
    bruteforce: bool = False
    loadable: bool = True
    load_error: str = ""
    poc_options: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def scan_directory(poc_dir: str) -> list[PocMeta]:
    metas: list[PocMeta] = []
    if not os.path.isdir(poc_dir):
        return metas
    for root, _dirs, files in os.walk(poc_dir):
        for filename in sorted(files):
            if not filename.endswith(".py") or filename.startswith("__"):
                continue
            path = os.path.join(root, filename)
            meta = read_metadata(path, poc_dir)
            if meta:
                metas.append(meta)
    _mark_name_conflicts(metas)
    return metas


def _mark_name_conflicts(metas: list[PocMeta]) -> None:
    """pocsuite3 用 pocs_<文件名> 作为注册键，同名文件在同一批次里只会真正加载第一个。"""
    stems: dict[str, int] = {}
    for meta in metas:
        stem = os.path.splitext(os.path.basename(meta.file_path))[0]
        stems[stem] = stems.get(stem, 0) + 1
    for meta in metas:
        stem = os.path.splitext(os.path.basename(meta.file_path))[0]
        if stems[stem] < 2:
            continue
        meta.loadable = False
        meta.load_error = f"与同目录下其他 {stems[stem] - 1} 个 POC 文件名相同，引擎按 pocs_{stem} 注册，只会加载第一个"


def read_metadata(path: str, poc_dir: str = "") -> PocMeta | None:
    poc_id = _poc_id(path, poc_dir)
    try:
        with warnings.catch_warnings(), open(path, encoding="utf-8") as handle:
            source = handle.read()
            # 第三方 POC 里常见 re.compile("\p{...}") 这类漏写 r 前缀的字符串，
            # 解析时只会刷屏 SyntaxWarning，与要抽取的元数据无关
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(source, filename=path)
    except (OSError, SyntaxError) as error:
        reason = f"解析失败: {error}"[:250]
        return PocMeta(poc_id=poc_id, file_path=path, errors=[str(error)],
                       loadable=False, load_error=reason)

    for node in tree.body:
        if isinstance(node, ast.ClassDef) and _is_poc_class(node):
            # 辅助函数可能定义在 POC 类外面，所以耗时/风险特征按整个模块扫描
            capabilities = _class_capabilities(node)
            capabilities.update(_dependency_flags(tree))
            capabilities["bruteforce"] = _uses_wordlist(tree)
            meta = _build_meta(path, poc_dir, _class_attributes(node), capabilities)
            _apply_loader_check(meta, source)
            return meta
    return PocMeta(poc_id=poc_id, file_path=path, errors=["未找到 POCBase 子类"],
                   loadable=False, load_error="未找到 POCBase 子类，pocsuite3 不会加载它")


# 与 pocsuite3 的 core.option._set_pocs_modules 用同一个判据：正文里没有这些特征的文件直接 continue，
# 引擎既不会加载也不会报错，列进扫描范围只会白等一轮超时。
# pocsuite2 风格的 register() 会被 pocsuite3 的 POC_IMPORTDICT 改写成 register_poc，同样可加载。
LOADER_PATTERN = re.compile(r"register_poc|\bregister\s*\(|matchers:\s+-")
NOT_LOADABLE = "脚本没有调用 register_poc/register，pocsuite3 不会加载它"


def _apply_loader_check(meta: PocMeta, source: str) -> None:
    if LOADER_PATTERN.search(source):
        return
    meta.loadable = False
    meta.load_error = NOT_LOADABLE


def _dependency_flags(tree: ast.AST) -> dict:
    """外部依赖类型：dnslog（可用设置的 OOB 域名解锁）、search（依赖搜索引擎），或两者都有。"""
    dnslog = _uses_symbols(tree, DNSLOG_SYMBOLS)
    search = _uses_symbols(tree, SEARCH_SYMBOLS)
    kind = "both" if dnslog and search else ("dnslog" if dnslog else ("search" if search else ""))
    return {"needs_oob": bool(kind), "oob_kind": kind}


def _uses_symbols(tree: ast.AST, names: set[str]) -> bool:
    """模块里是否调用了这些名字（构造 ceye/fofa 客户端、起反连 HTTP 服务等）。"""
    for stmt in ast.walk(tree):
        if isinstance(stmt, ast.Call):
            func = stmt.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name in names:
                return True
    return False


def _uses_wordlist(tree: ast.AST) -> bool:
    """是否引用 pocsuite3 自带的口令字典（paths.WEAK_PASS / MYSQL_PASS / REDIS_PASS …）。

    这类 POC 是凭据爆破，单个目标能发出上万次请求，既慢又会在目标上留下账号锁定风险。
    """
    for stmt in ast.walk(tree):
        if isinstance(stmt, ast.Attribute) and stmt.attr.endswith(("_PASS", "_USER")):
            return True
        if isinstance(stmt, ast.Name) and stmt.id.endswith(("_PASS", "_USER")):
            return True
        if isinstance(stmt, ast.FunctionDef) and stmt.name == "get_word_list":
            return True
    return False


def _is_poc_class(node: ast.ClassDef) -> bool:
    for base in node.bases:
        name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
        if name == "POCBase":
            return True
    return False


def _class_attributes(node: ast.ClassDef) -> dict:
    values: dict[str, object] = {}
    for stmt in node.body:
        if isinstance(stmt, ast.Assign):
            targets = stmt.targets
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            targets = [stmt.target]
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                values[target.id] = _literal(stmt.value)
                break
    return values


def _literal(value):
    if value is None:
        return ""
    try:
        return ast.literal_eval(value)
    except (ValueError, SyntaxError, TypeError):
        if isinstance(value, ast.Attribute):
            return value.attr
        return ast.unparse(value)[:120]


def _read_class_references(node: ast.ClassDef) -> list[str]:
    """references 是类里的裸列表字面量，元素常带行内注释，literal_eval 解析不了，单独按行抽取。"""
    for stmt in node.body:
        if not isinstance(stmt, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "references" for target in stmt.targets):
            continue
        if not isinstance(stmt.value, (ast.List, ast.Tuple)):
            return _reference_links(_literal(stmt.value))
        links: list[str] = []
        for element in stmt.value.elts:
            for part in re.split(r"[,\n]", str(_literal(element) or "")):
                url = part.strip()
                if url.startswith(("http://", "https://")) and url not in links:
                    links.append(url)
        return links[:MAX_REFS]
    return []


def _attack_supported(node: ast.ClassDef) -> bool:
    """仅 `return self._verify()` 的 _attack 只是兼容占位，不算实现 attack 模式。"""
    for stmt in node.body:
        if not isinstance(stmt, ast.FunctionDef) or stmt.name != "_attack":
            continue
        body = [
            item for item in stmt.body
            if not (isinstance(item, ast.Expr) and isinstance(item.value, ast.Constant)
                    and isinstance(item.value.value, str))
        ]
        if len(body) == 1 and isinstance(body[0], ast.Return):
            value = body[0].value
            if (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                    and value.func.attr == "_verify" and not value.args and not value.keywords):
                return False
        return True
    return False


def _class_capabilities(node: ast.ClassDef) -> dict:
    """探测 POC 实现了哪些执行模式与可注入参数，前端据此展示交互控件。"""
    options: list[dict] = []
    for stmt in node.body:
        if not isinstance(stmt, ast.FunctionDef):
            continue
        if stmt.name == "_options":
            options.extend(_option_declarations(stmt))
    return {
        "supports_attack": _attack_supported(node),
        "supports_shell": any(isinstance(s, ast.FunctionDef) and s.name == "_shell" for s in node.body),
        "references": _read_class_references(node),
        "poc_options": options[:20],
    }


def _option_declarations(func: ast.FunctionDef) -> list[dict]:
    """抽取 o['cmd'] = OptString('uname -a', description=...) 形式的选项声明。"""
    declared: list[dict] = []
    for stmt in ast.walk(func):
        if not isinstance(stmt, ast.Assign) or not stmt.targets:
            continue
        target = stmt.targets[0]
        if not isinstance(target, ast.Subscript) or not isinstance(target.slice, ast.Constant):
            continue
        value = stmt.value
        if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                and value.func.id.startswith("Opt")):
            continue
        default = next((keyword.value for keyword in value.keywords if keyword.arg == "default"), None)
        if default is None and value.args:
            default = value.args[0]
        declared.append({
            "name": str(target.slice.value),
            "type": value.func.id,
            "default": _short(_literal(default)),
            "description": _short(_literal(_keyword(value, "description"))),
            "required": _literal(_keyword(value, "require")) in (True, "True"),
        })
    return declared


def _keyword(call: ast.Call, name: str):
    return next((keyword.value for keyword in call.keywords if keyword.arg == name), None)


def _short(value) -> str:
    if isinstance(value, (tuple, list)):
        return ", ".join(str(item) for item in value)[:200]
    return str(value)[:200]


def _build_meta(path: str, poc_dir: str, values: dict, capabilities: dict) -> PocMeta:
    vul_type = str(values.get("vulType") or values.get("vul_type") or "")
    severity = str(values.get("severity") or "").lower()
    if severity not in ("critical", "high", "medium", "low", "info"):
        severity = SEVERITY_BY_VUL_TYPE.get(vul_type.upper(), "medium")
    description = str(values.get("desc") or values.get("description") or "")
    return PocMeta(
        poc_id=_poc_id(path, poc_dir),
        file_path=path,
        name=str(values.get("name") or os.path.splitext(os.path.basename(path))[0]),
        app_name=str(values.get("appName") or ""),
        severity=severity,
        # pocsuite3 的默认 vulID 是 "0"，表示脚本没有声明，入库时统一按未标注处理
        vul_id="" if str(values.get("vulID") or "0") == "0" else str(values.get("vulID")),
        vul_type=vul_type,
        description=description[:2000],
        **capabilities,
    )


MAX_REFS = 10


def _reference_links(value) -> list[str]:
    """规范化 POC 里的 references：模板给的是 {'reference_url': …}，实际脚本里多是字符串列表。"""
    if isinstance(value, dict):
        items = list(value.values())
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        items = [value]
    links: list[str] = []
    for item in items:
        for part in re.split(r"[,\n]", str(item or "")):
            url = part.strip()
            # 只收 http(s)：POC 是第三方脚本，references 里写 javascript: 之类的不该变成页面链接
            if url.startswith(("http://", "https://")) and url not in links:
                links.append(url)
    return links[:MAX_REFS]


def _poc_id(path: str, poc_dir: str) -> str:
    if poc_dir and os.path.abspath(path).startswith(os.path.abspath(poc_dir)):
        relative = os.path.relpath(path, poc_dir)
        stem = relative[: -len(".py")].replace(os.sep, "/")
        return stem if stem.count("/") <= 1 else stem.replace("/", "_")
    return os.path.splitext(os.path.basename(path))[0]


def sync_registry(poc_dir: str, db_session) -> dict:
    """把目录里的 POC 同步进 poc_registry，保留人工启用/停用状态。"""
    from ...models import PocRegistry

    if not os.path.isdir(poc_dir):
        # 路径配错或外部盘未挂载时，扫描结果为空不代表用户删光了 POC，不能清空现有索引
        return {"added": 0, "updated": 0, "removed": 0, "total": 0,
                "unloadable": 0, "missing": True}

    metas = scan_directory(poc_dir)
    existing = {row.poc_id: row for row in PocRegistry.query.all()}
    added = updated = 0

    for meta in metas:
        row = existing.get(meta.poc_id)
        if row is None:
            row = PocRegistry(poc_id=meta.poc_id)
            db_session.add(row)
            added += 1
        else:
            updated += 1
        row.name = meta.name or meta.poc_id
        row.app_name = meta.app_name
        row.severity = meta.severity
        row.file_path = meta.file_path
        row.description = meta.description or (meta.errors[0] if meta.errors else "")
        row.vul_id = meta.vul_id
        row.vul_type = meta.vul_type
        row.supports_attack = 1 if meta.supports_attack else 0
        row.supports_shell = 1 if meta.supports_shell else 0
        row.needs_oob = 1 if meta.needs_oob else 0
        row.oob_kind = meta.oob_kind
        row.bruteforce = 1 if meta.bruteforce else 0
        row.loadable = 1 if meta.loadable else 0
        row.load_error = "" if meta.loadable else (meta.load_error or (meta.errors[0] if meta.errors else ""))
        row.poc_refs = meta.references
        row.poc_options = meta.poc_options
        row.indexed_at = utcnow()
        existing.pop(meta.poc_id, None)

    removed = 0
    for stale in existing.values():
        db_session.delete(stale)
        removed += 1
    db_session.commit()
    return {"added": added, "updated": updated, "removed": removed, "total": len(metas),
            "unloadable": sum(1 for meta in metas if not meta.loadable), "missing": False}
