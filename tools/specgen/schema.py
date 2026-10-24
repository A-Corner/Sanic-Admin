# -*- coding: utf-8 -*-
"""
规格 schema（pydantic 校验）。

规格是唯一事实源，只描述「业务资源是什么」，不含任何渲染层语法（AMIS 等）。
所有模型 ``extra="forbid"``：规格里出现未知键（包括误写进来的 AMIS 键）直接报错。
"""

import keyword
import re
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

IDENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")

#: 框架已占用的资源名（权限点 / 路由），规格不得重名
RESERVED_RESOURCES = frozenset(
    {"account", "role", "profile", "log", "setting", "file", "dashboard", "system", "session", "verification", "upload"}
)
#: 模型内置属性名，字段不得重名
RESERVED_FIELDS = frozenset({"id", "created_at", "updated_at", "deleted", "json", "validate", "pk", "save", "delete"})
#: belongs_to 可指向的框架内置模型（资源名 -> 模型类名）
CORE_TARGETS = {"account": "Account"}

FieldType = Literal["string", "text", "int", "float", "bool", "date", "datetime"]
Action = Literal["read", "create", "update", "delete"]


class SpecError(Exception):
    """规格不合法。``errors`` 是 ``[(字段路径, 原因)]``。"""

    def __init__(self, source: str, errors: List[tuple]):
        self.source = source
        self.errors = errors
        super().__init__("\n".join(f"{source}: {path}: {reason}" for path, reason in errors))


def _ident(value: str, what: str) -> str:
    if not IDENT_RE.match(value):
        raise ValueError(f"{what}必须匹配 {IDENT_RE.pattern}（小写字母开头，仅小写字母/数字/下划线）")
    if keyword.iskeyword(value):
        raise ValueError(f"{what}不能是 Python 关键字")
    return value


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FieldSpec(_Strict):
    name: str
    type: FieldType
    label: Optional[str] = None
    required: bool = False
    default: Any = None
    choices: Optional[List[Any]] = None
    max_length: Optional[int] = Field(default=None, ge=1, le=4096)
    format: Optional[Literal["email"]] = None
    unique: bool = False
    list: bool = False
    searchable: bool = False

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        _ident(v, "字段名")
        if v in RESERVED_FIELDS:
            raise ValueError(f"字段名 {v!r} 是保留名")
        return v

    @model_validator(mode="after")
    def _check(self):
        t = self.type
        if self.max_length is not None and t != "string":
            raise ValueError("max_length 仅 string 类型可用")
        if self.format is not None and t != "string":
            raise ValueError("format 仅 string 类型可用")
        if self.unique and t in ("text", "bool"):
            raise ValueError(f"{t} 类型不支持 unique")
        if self.searchable and t not in ("string", "text"):
            raise ValueError("searchable 仅 string/text 类型可用")
        if self.choices is not None:
            if t not in ("string", "int"):
                raise ValueError("choices 仅 string/int 类型可用")
            if not self.choices:
                raise ValueError("choices 不能为空")
            if len(set(map(repr, self.choices))) != len(self.choices):
                raise ValueError("choices 含重复值")
            py = str if t == "string" else int
            for c in self.choices:
                if type(c) is not py:
                    raise ValueError(f"choices 值 {c!r} 与字段类型 {t} 不符")
            if self.format:
                raise ValueError("choices 与 format 互斥")
        if self.default is not None:
            if self.required:
                raise ValueError("required 与 default 互斥（有默认值的字段无需必填）")
            ok = {
                "string": lambda v: isinstance(v, str),
                "text": lambda v: isinstance(v, str),
                "int": lambda v: type(v) is int,
                "float": lambda v: type(v) in (int, float),
                "bool": lambda v: type(v) is bool,
            }[t]
            if not ok(self.default):
                raise ValueError(f"default {self.default!r} 与字段类型 {t} 不符")
            if self.choices is not None and self.default not in self.choices:
                raise ValueError(f"default {self.default!r} 不在 choices 内")
            if t == "string" and len(self.default) > (self.max_length or 255):
                raise ValueError("default 超过 max_length")
        if t == "string" and self.max_length is None:
            self.max_length = 255
        if t == "string" and self.choices:
            longest = max(len(c) for c in self.choices)
            if longest > self.max_length:
                raise ValueError(f"choices 中有值长度 {longest} 超过 max_length {self.max_length}")
        return self

    @property
    def title(self) -> str:
        return self.label or self.name


class BelongsToSpec(_Strict):
    name: str
    target: str
    label: Optional[str] = None
    required: bool = False
    list: bool = False

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        _ident(v, "belongs_to 名")
        if v in RESERVED_FIELDS:
            raise ValueError(f"名称 {v!r} 是保留名")
        return v

    @field_validator("target")
    @classmethod
    def _target(cls, v):
        return _ident(v, "target")

    @property
    def title(self) -> str:
        return self.label or self.name

    @property
    def column(self) -> str:
        return f"{self.name}_id"


class PermissionsSpec(_Strict):
    actions: List[Action] = ["read", "create", "update", "delete"]

    @model_validator(mode="after")
    def _check(self):
        if len(set(self.actions)) != len(self.actions):
            raise ValueError("actions 含重复项")
        if set(self.actions) != {"read", "create", "update", "delete"}:
            raise ValueError("当前版本要求 actions 恰为 read/create/update/delete 四项")
        return self


class MenuSpec(_Strict):
    icon: str = "fa-table"
    order: int = Field(default=100, ge=0, le=9999)
    label: Optional[str] = None


class SortingSpec(_Strict):
    """列表排序：默认字段与允许排序的字段白名单（未列入的一律 400）。"""

    default: Optional[str] = None
    allowed: List[str] = []


class ResourceSpec(_Strict):
    resource: str
    table: Optional[str] = None
    plural: Optional[str] = None
    label: Optional[str] = None
    description: str = ""
    fields: List[FieldSpec] = []
    belongs_to: List[BelongsToSpec] = []
    permissions: PermissionsSpec = PermissionsSpec()
    menu: MenuSpec = MenuSpec()
    #: (c) 排序配置；`allowed` 为空表示不允许任何排序参数（?ordering= 一律 400）
    sorting: SortingSpec = SortingSpec()
    #: (d) 软删除：开启后 DELETE 只置 deleted，列表/详情默认过滤已删除行
    soft_delete: bool = False

    #: 以下为加载时填充的非规格属性
    source: str = Field(default="", exclude=True)
    digest: str = Field(default="", exclude=True)

    @field_validator("resource")
    @classmethod
    def _resource(cls, v):
        _ident(v, "resource")
        if v in RESERVED_RESOURCES:
            raise ValueError(f"resource {v!r} 与框架内置资源冲突")
        return v

    @field_validator("plural")
    @classmethod
    def _plural(cls, v):
        return v if v is None else _ident(v, "plural")

    @model_validator(mode="after")
    def _check(self):
        self.table = self.table or self.resource
        self.plural = self.plural or f"{self.resource}s"
        self.label = self.label or self.resource
        if not self.fields and not self.belongs_to:
            raise ValueError("至少需要一个字段或 belongs_to")
        seen = set()
        for item in [*self.fields, *self.belongs_to]:
            key = item.name
            col = f"{key}_id" if isinstance(item, BelongsToSpec) else key
            for k in (key, col):
                if k in seen:
                    raise ValueError(f"字段/关系名重复: {k!r}")
            seen.update({key, col})
        return self

    @property
    def cls(self) -> str:
        return "".join(p.capitalize() for p in self.resource.split("_"))

    @property
    def write_fields(self) -> List[str]:
        return [*(f.name for f in self.fields), *(b.column for b in self.belongs_to)]


def _fmt_errors(exc: ValidationError) -> List[tuple]:
    out = []
    for e in exc.errors():
        path = ".".join(str(p) for p in e["loc"]) or "<root>"
        msg = e["msg"]
        if msg.startswith("Value error, "):
            msg = msg[len("Value error, ") :]
        out.append((path, msg))
    return out


def load_spec(path: Path, rel: str) -> ResourceSpec:
    """读取并校验一份规格；失败抛 ``SpecError``（含字段路径与原因）。"""
    raw = path.read_bytes()
    try:
        data = yaml.safe_load(raw.decode("utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise SpecError(rel, [("<yaml>", str(exc).replace("\n", " "))])
    if not isinstance(data, dict):
        raise SpecError(rel, [("<root>", "规格顶层必须是映射")])
    try:
        spec = ResourceSpec.model_validate(data)
    except ValidationError as exc:
        raise SpecError(rel, _fmt_errors(exc))
    import hashlib

    spec.source = rel
    spec.digest = hashlib.sha256(raw).hexdigest()[:12]
    if path.stem != spec.resource:
        raise SpecError(rel, [("resource", f"文件名 {path.stem!r} 必须与 resource {spec.resource!r} 一致")])
    return spec


def load_specs(spec_dir: Path, rel_dir: str = "specs") -> Dict[str, ResourceSpec]:
    """加载目录下全部规格并做跨规格校验（resource/table/plural 唯一、belongs_to 目标存在、无环）。"""
    specs: Dict[str, ResourceSpec] = {}
    for p in sorted(spec_dir.glob("*.yaml")):
        s = load_spec(p, f"{rel_dir}/{p.name}")
        specs[s.resource] = s
    errors = []
    for kind in ("table", "plural"):
        owner: Dict[str, str] = {}
        for s in specs.values():
            v = getattr(s, kind)
            if v in owner:
                errors.append((s.source, kind, f"{kind} {v!r} 与 {owner[v]} 重复"))
            owner[v] = s.source
    for s in specs.values():
        for i, b in enumerate(s.belongs_to):
            path = f"belongs_to.{i}.target"
            if b.target in CORE_TARGETS:
                if b.required:
                    errors.append((s.source, f"belongs_to.{i}.required", "指向框架内置模型的关系只能是可选"))
            elif b.target not in specs:
                errors.append((s.source, path, f"目标资源 {b.target!r} 不存在（已知: {sorted(specs)}）"))
            elif b.target == s.resource:
                errors.append((s.source, path, "不支持自引用"))

    # 环检测（A->B->A 会让测试无法造数据）
    def reaches(a: str, b: str, seen=()) -> bool:
        if a in seen or a not in specs:
            return False
        return any(t.target == b or reaches(t.target, b, (*seen, a)) for t in specs[a].belongs_to)

    for s in specs.values():
        if reaches(s.resource, s.resource):
            errors.append((s.source, "belongs_to", "存在循环依赖"))
    if errors:
        raise SpecError("specs", [(f"{src}:{path}", reason) for src, path, reason in errors])
    return specs
