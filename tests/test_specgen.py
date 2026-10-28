#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""specgen 生成器自身的测试：规格校验、确定性、golden 漂移（含正向对照）、权限接线与全权限角色判定。"""

import copy
import shutil
from pathlib import Path

import pytest
import yaml

from tools.specgen import generate
from tools.specgen.render_py import MARK
from tools.specgen.schema import SpecError, load_spec, load_specs

ROOT = Path(__file__).resolve().parent.parent


def _write(tmp_path, data, name="thing.yaml"):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return p


def _base():
    return {"resource": "thing", "fields": [{"name": "title", "type": "string", "required": True}]}


# ---------------------------------------------------------------------------
# 1. 规格校验：非法规格必须报「字段路径 + 原因」
# ---------------------------------------------------------------------------


def _mut(fn):
    d = copy.deepcopy(_base())
    fn(d)
    return d


BAD_SPECS = [
    ("unknown_type", _mut(lambda d: d["fields"][0].update(type="blob")), "fields.0.type", "Input should be"),
    ("amis_key_rejected", _mut(lambda d: d.update(columns=[{"type": "text"}])), "columns", "Extra inputs are not permitted"),
    ("amis_key_in_field", _mut(lambda d: d["fields"][0].update(amis={"type": "input-text"})), "fields.0.amis", "Extra inputs"),
    ("bad_ident", _mut(lambda d: d.update(resource="Bad-Name")), "resource", "必须匹配"),
    ("reserved_resource", _mut(lambda d: d.update(resource="account")), "resource", "与框架内置资源冲突"),
    ("reserved_spec_permission", _mut(lambda d: d.update(resource="spec")), "resource", "与框架内置资源冲突"),
    ("reserved_field", _mut(lambda d: d["fields"][0].update(name="id")), "fields.0.name", "保留名"),
    (
        "default_not_in_choices",
        _mut(lambda d: d["fields"][0].update(required=False, choices=["a", "b"], default="c")),
        "fields.0",
        "不在 choices 内",
    ),
    ("required_and_default", _mut(lambda d: d["fields"][0].update(default="x")), "fields.0", "required 与 default 互斥"),
    ("choices_type_mismatch", _mut(lambda d: d["fields"][0].update(choices=["a", 1])), "fields.0", "与字段类型 string 不符"),
    ("empty_choices", _mut(lambda d: d["fields"][0].update(choices=[])), "fields.0", "choices 不能为空"),
    (
        "max_length_on_int",
        _mut(lambda d: d["fields"].append({"name": "n", "type": "int", "max_length": 5})),
        "fields.1",
        "max_length 仅 string",
    ),
    (
        "unique_on_text",
        _mut(lambda d: d["fields"].append({"name": "t", "type": "text", "unique": True})),
        "fields.1",
        "不支持 unique",
    ),
    ("duplicate_name", _mut(lambda d: d["fields"].append({"name": "title", "type": "text"})), "<root>", "字段/关系名重复"),
    ("no_fields", _mut(lambda d: d.update(fields=[])), "<root>", "至少需要一个字段"),
    ("bad_actions", _mut(lambda d: d.update(permissions={"actions": ["read"]})), "permissions", "恰为"),
    (
        "max_length_range",
        _mut(lambda d: d["fields"][0].update(max_length=0)),
        "fields.0.max_length",
        "greater than or equal to 1",
    ),
]


@pytest.mark.parametrize("case,data,path,reason", BAD_SPECS, ids=[c[0] for c in BAD_SPECS])
def test_invalid_spec_reports_path_and_reason(tmp_path, case, data, path, reason):
    p = _write(tmp_path, data)
    with pytest.raises(SpecError) as exc:
        load_spec(p, "specs/thing.yaml")
    paths = [(pth, why) for pth, why in exc.value.errors]
    assert any(pth == path and reason in why for pth, why in paths), paths
    assert "specs/thing.yaml" in str(exc.value)


def test_valid_spec_is_accepted(tmp_path):
    """正向对照：基础规格合法，上面的失败确实来自各自的变异。"""
    spec = load_spec(_write(tmp_path, _base()), "specs/thing.yaml")
    assert spec.resource == "thing" and spec.plural == "things"


def test_filename_must_match_resource(tmp_path):
    p = _write(tmp_path, _base(), name="other.yaml")
    with pytest.raises(SpecError) as exc:
        load_spec(p, "specs/other.yaml")
    assert "必须与 resource" in str(exc.value)


def test_yaml_syntax_error_reported(tmp_path):
    p = tmp_path / "thing.yaml"
    p.write_text("resource: [unclosed\n", encoding="utf-8")
    with pytest.raises(SpecError) as exc:
        load_spec(p, "specs/thing.yaml")
    assert exc.value.errors[0][0] == "<yaml>"


def test_belongs_to_unknown_target_and_cycle(tmp_path):
    a = {"resource": "aa", "fields": [{"name": "n", "type": "string"}], "belongs_to": [{"name": "bb", "target": "bb"}]}
    _write(tmp_path, a, "aa.yaml")
    with pytest.raises(SpecError) as exc:
        load_specs(tmp_path)
    assert "目标资源 'bb' 不存在" in str(exc.value)
    assert "belongs_to.0.target" in str(exc.value)

    b = {"resource": "bb", "fields": [{"name": "n", "type": "string"}], "belongs_to": [{"name": "aa", "target": "aa"}]}
    _write(tmp_path, b, "bb.yaml")
    with pytest.raises(SpecError) as exc:
        load_specs(tmp_path)
    assert "循环依赖" in str(exc.value)


# ---------------------------------------------------------------------------
# 2. 确定性与标记
# ---------------------------------------------------------------------------


def _mini_root(tmp_path, name="root"):
    """最小项目根：只含 site.json 与 specs（生成器 compute 只需要这些）。"""
    root = tmp_path / name
    (root / "amis/pages").mkdir(parents=True)
    shutil.copy(ROOT / "amis/pages/site.json", root / "amis/pages/site.json")
    shutil.copytree(ROOT / "specs", root / "specs")
    return root


def test_generation_is_byte_deterministic(tmp_path):
    outs = []
    for i in range(2):
        root = _mini_root(tmp_path, f"r{i}")
        outs.append(generate.compute(root, load_specs(root / "specs")))
    assert outs[0].keys() == outs[1].keys()
    for rel in outs[0]:
        assert outs[0][rel].encode() == outs[1][rel].encode(), rel
    # 生成后再生成一次（含 site.json 合并）仍然不变：幂等
    root = _mini_root(tmp_path, "r2")
    generate.run(root, root / "specs")
    changed, stale = generate.run(root, root / "specs")
    assert changed == [] and stale == []


def test_generated_files_carry_marker():
    wanted = generate.compute(ROOT, load_specs(ROOT / "specs"))
    for rel, content in wanted.items():
        if rel == generate.SITE:
            continue  # site.json 是混合文件，标记在菜单项的 x-specgen 键上
        assert MARK in content, rel
    assert '"x-specgen": "customer"' in wanted[generate.SITE]


# ---------------------------------------------------------------------------
# 3. golden：已提交的生成物 = 规格的确定性输出；改规格而不重新生成必须失败
# ---------------------------------------------------------------------------


def assert_no_drift(root: Path):
    changed, stale = generate.diff(root, generate.compute(root, load_specs(root / "specs")))
    assert not changed and not stale, f"生成物与规格漂移: changed={changed} stale={stale}"


def test_golden_committed_artifacts_match_specs():
    assert_no_drift(ROOT)


def test_golden_positive_control_spec_change_breaks_snapshot(tmp_path):
    """正向对照：复制仓库生成物，只改规格（多一个 choice）而不重新生成，快照检查必须失败。"""
    root = tmp_path / "proj"
    for sub in ("app/generated", "tests/generated", "amis/pages", "specs"):
        shutil.copytree(ROOT / sub, root / sub)
    assert_no_drift(root)  # 改前干净

    spec = root / "specs/customer.yaml"
    data = yaml.safe_load(spec.read_text(encoding="utf-8"))
    status = next(f for f in data["fields"] if f["name"] == "status")
    status["choices"].append("vip")
    spec.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")

    with pytest.raises(AssertionError) as exc:
        assert_no_drift(root)
    msg = str(exc.value)
    assert "app/generated/resources/customer.py" in msg and "amis/pages/customer-list.json" in msg

    # 重新生成后恢复一致，并且 choices 贯通到 模型 / API / AMIS / 测试
    generate.run(root, root / "specs")
    assert_no_drift(root)
    assert "'vip'" in (root / "app/generated/resources/customer.py").read_text(encoding="utf-8")
    assert '"vip"' in (root / "amis/pages/customer-list.json").read_text(encoding="utf-8")


def test_stale_generated_files_are_removed(tmp_path):
    root = _mini_root(tmp_path)
    generate.run(root, root / "specs")
    (root / "specs/order.yaml").unlink()
    (root / "specs/customer.yaml").unlink()
    shutil.copy(ROOT / "specs/customer.yaml", root / "specs/customer.yaml")
    changed, stale = generate.run(root, root / "specs")
    assert "app/generated/resources/order.py" in stale
    assert not (root / "app/generated/resources/order.py").exists()
    assert not (root / "amis/pages/order-list.json").exists()
    assert "order" not in (root / "amis/pages/site.json").read_text(encoding="utf-8")


def test_check_hand_authored_files_are_never_deleted(tmp_path):
    """没有标记的文件（手写页面）即使匹配 glob 也不能被当作陈旧文件删除。"""
    root = _mini_root(tmp_path)
    (root / "amis/pages/role-list.json").write_text('{"type": "crud"}', encoding="utf-8")
    generate.run(root, root / "specs")
    assert (root / "amis/pages/role-list.json").exists()


# ---------------------------------------------------------------------------
# 4. 全链路属性贯通 / 权限接线 / 全权限角色
# ---------------------------------------------------------------------------


def test_field_attributes_flow_through_model_api_and_amis():
    out = generate.compute(ROOT, load_specs(ROOT / "specs"))
    model = out["app/generated/models/customer.py"]
    api = out["app/generated/resources/customer.py"]
    page = out["amis/pages/customer-list.json"]
    assert "unique=True" in model and "default='active'" in model and "max_length=128" in model
    assert "OneOf(['active', 'inactive', 'archived'])" in api and "Length(max_=128)" in api and "Required()" in api
    assert "UNIQUE_FIELDS = ('email',)" in api
    assert '"type": "select"' in page and '"maxLength": 128' in page and '"value": "active"' in page
    order_model = out["app/generated/models/order.py"]
    assert "ForeignKeyField('models.Customer'" in order_model and "RESTRICT" in order_model
    assert '"customer_id": self.customer_id' in order_model
    # FK_TARGETS 现为 (模型, 目标资源) 元组——权限判定需要资源名（防 ID 枚举）
    assert "'customer_id': (Customer, 'customer')" in out["app/generated/resources/order.py"]


def test_permissions_and_menu_auto_registered():
    import app.api.resources  # noqa: F401  导入即触发生成资源的权限注册
    from app.auth.permissions import ALL_PERMISSIONS, admin_all_permissions

    # 从 specs/ 动态取资源名——写死 ("customer", "order") 会在每加一个资源时
    # 假失败（M3 加 ticket 就撞上了），而这条测试的本意是「**所有**生成资源
    # 都自动注册了权限与菜单」，不是「恰好只有这两个」。
    from tools.specgen.schema import load_specs

    expected = sorted(load_specs(ROOT / "specs", "specs"))
    assert expected, "specs/ 下没有资源，用例前提不成立"
    for res in expected:
        assert ALL_PERMISSIONS[res] == ["read", "create", "update", "delete"], res
        assert admin_all_permissions()[res] == ["all"], res
    import json

    pages = json.loads((ROOT / "amis/pages/site.json").read_text(encoding="utf-8"))["data"]["pages"]
    generated = sorted(p["x-specgen"] for p in pages if "x-specgen" in p)
    assert generated == expected, f"菜单里缺资源：{set(expected) - set(generated)}"


def test_full_permission_role_still_protected_after_generated_resources():
    """
    风险评估（role.py `_role_grants_all_permissions`）：新增权限点后，存量「全权限」角色
    （覆盖了当时注册表全部资源）不能因为没覆盖新生成的资源而失去受保护管理员身份。
    """
    import app.api.resources  # noqa: F401
    from app.api.resources.role import _role_grants_all_permissions
    from app.auth.permissions import all_resources
    from app.generated.permissions import GENERATED_PERMISSIONS
    from app.models import Role

    core = [r for r in all_resources() if r not in GENERATED_PERMISSIONS]
    assert core and GENERATED_PERMISSIONS, "前置：既有核心资源与生成资源都存在"
    legacy_full = Role(name="legacy-full", permissions={r: ["all"] for r in core})

    # 风险真实存在：按「注册表全部资源」计算，这个存量全权限角色并未覆盖生成资源
    assert not all(r in legacy_full.permissions for r in all_resources())
    # 修复后仍判定为全权限
    assert _role_grants_all_permissions(legacy_full) is True

    # 覆盖生成资源的全权限角色（含内置 admin 同步后的形态）同样为 True
    admin_like = Role(name="admin-like", permissions={r: ["all"] for r in all_resources()})
    assert _role_grants_all_permissions(admin_like) is True

    # 正向对照：缺任一核心资源 -> False；动作不全 -> False
    missing = dict(legacy_full.permissions)
    missing.pop("account")
    assert _role_grants_all_permissions(Role(name="m", permissions=missing)) is False
    partial = dict(legacy_full.permissions, role=["read"])
    assert _role_grants_all_permissions(Role(name="p", permissions=partial)) is False


# ---------------------------------------------------------------------------
# M1：sorting / soft_delete / date 的规格校验
# ---------------------------------------------------------------------------


def _spec_with(**extra):
    data = {
        "resource": "thing",
        "fields": [{"name": "title", "type": "string"}],
        **extra,
    }
    return data


def test_sorting_allowed_must_reference_existing_field(tmp_path):
    """sorting.allowed 里写了不存在的字段 -> 规格错误。"""
    p = _write(tmp_path, _spec_with(sorting={"allowed": ["title", "nope"]}))
    with pytest.raises(SpecError) as exc:
        load_spec(p, "specs")
    assert any("不存在的字段" in reason for _, reason in exc.value.errors)


def test_sorting_default_must_be_in_allowed(tmp_path):
    """sorting.default 不在 allowed 里 -> 规格错误。"""
    p = _write(tmp_path, _spec_with(sorting={"default": "title", "allowed": ["id"]}))
    with pytest.raises(SpecError) as exc:
        load_spec(p, "specs")
    assert any("不在 sorting.allowed 内" in reason for _, reason in exc.value.errors)


def test_sorting_default_must_reference_existing_field(tmp_path):
    """sorting.default 指向不存在的字段 -> 规格错误。"""
    p = _write(tmp_path, _spec_with(sorting={"default": "ghost"}))
    with pytest.raises(SpecError) as exc:
        load_spec(p, "specs")
    assert any("不存在的字段" in reason for _, reason in exc.value.errors)


def test_soft_delete_must_be_boolean(tmp_path):
    """soft_delete 写成字符串（YAML 里 'yes'/'true'）-> 规格错误，不静默当真值。"""
    p = _write(tmp_path, _spec_with(soft_delete="yes"))
    with pytest.raises(SpecError) as exc:
        load_spec(p, "specs")
    assert any("必须是布尔值" in reason for _, reason in exc.value.errors)


def test_date_field_rejects_max_length(tmp_path):
    """date/datetime 字段配 max_length -> 规格错误（仅 string 可用）。"""
    p = _write(
        tmp_path,
        {
            "resource": "thing",
            "fields": [{"name": "when", "type": "date", "max_length": 10}],
        },
    )
    with pytest.raises(SpecError) as exc:
        load_spec(p, "specs")
    assert any("max_length 仅 string" in reason for _, reason in exc.value.errors)


def test_sorting_and_soft_delete_valid_spec_loads(tmp_path):
    """正向对照：合法配置能加载，且字段被正确解析。"""
    p = _write(
        tmp_path,
        _spec_with(
            sorting={"default": "-id", "allowed": ["id", "title"]},
            soft_delete=True,
        ),
    )
    spec = load_spec(p, "specs")
    assert spec.sorting.allowed == ["id", "title"]
    assert spec.soft_delete is True


def test_customer_spec_has_m1_features():
    """仓库内的 customer 示例规格启用了 date/sorting/soft_delete（端到端样例）。"""
    specs = load_specs(ROOT / "specs", "specs")
    customer = specs["customer"]
    assert customer.soft_delete is True
    assert "birthday" in customer.sorting.allowed
    assert any(f.type == "date" for f in customer.fields)
    assert any(f.type == "datetime" for f in customer.fields)


# ---------------------------------------------------------------------------
# AMIS 表单控件映射：每个 FieldType 都必须产出带 type 的控件
# ---------------------------------------------------------------------------


def _all_field_types():
    """从 schema 的 ``FieldType``（Literal）里取出全部取值，不手抄。"""
    import typing

    from tools.specgen.schema import FieldType

    args = typing.get_args(FieldType)
    assert args, "FieldType 不是 Literal，取不到取值列表"
    return list(args)


@pytest.mark.parametrize("field_type", _all_field_types())
def test_every_field_type_maps_to_amis_control_with_type(field_type):
    """
    每个 FieldType 取值都必须映射出**带 type** 的 AMIS 控件。

    早先 `_control()` 漏了 date / datetime 两个分支，生成的字段是个没有
    `type` 的对象；AMIS 报「找不到对应的渲染器」，**整个新增/编辑弹窗无法提交**。
    而 API 测试、单元测试、CI 全绿——只有真跑浏览器才会暴露。

    这里遍历 `FieldType` 的**全部取值**（从 Literal 读，不手抄），
    新增类型却忘了加映射时，这条会红。
    """
    from tools.specgen.render_amis import _control
    from tools.specgen.schema import FieldSpec

    f = FieldSpec(name="probe", type=field_type, label="探针")
    ctrl = _control(f, {})
    assert ctrl.get("type"), f"FieldType={field_type!r} 生成的控件没有 type：{ctrl}"
    assert isinstance(ctrl["type"], str) and ctrl["type"]


def test_choices_field_maps_to_select():
    """choices 字段映射成 select。"""
    from tools.specgen.render_amis import _control
    from tools.specgen.schema import FieldSpec

    f = FieldSpec(name="probe", type="string", label="探针", choices=["a", "b"])
    ctrl = _control(f, {})
    assert ctrl["type"] == "select"
    assert [o["value"] for o in ctrl["options"]] == ["a", "b"]


def test_belongs_to_maps_to_select_with_source():
    """belongs_to 字段映射成带 source 的 select。"""
    from tools.specgen.render_amis import _control
    from tools.specgen.schema import load_specs

    specs = load_specs(Path("specs"), "specs")
    order = specs["order"]
    rel = order.belongs_to[0]
    ctrl = _control(rel, specs)
    assert ctrl["type"] == "select"
    assert "source" in ctrl, f"外键控件缺少 source：{ctrl}"


def test_control_raises_on_unmapped_type():
    """
    兜底：遇到没有映射的类型必须**直接 raise**，而不是产出无 type 的控件。

    这条守的是「新增 FieldType 却忘了加分支」的将来时。
    """
    from tools.specgen.render_amis import _control
    from tools.specgen.schema import FieldSpec

    f = FieldSpec(name="probe", type="string", label="探针")
    # 绕过 pydantic 校验，模拟「schema 加了新类型但 render 没跟上」
    object.__setattr__(f, "type", "brand_new_type")
    object.__setattr__(f, "choices", None)
    with pytest.raises(ValueError, match="缺少映射"):
        _control(f, {})
