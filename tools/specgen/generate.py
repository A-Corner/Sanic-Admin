# -*- coding: utf-8 -*-
"""生成编排：规格 -> 文件集合（纯计算，确定）；写盘 / 漂移检查 / 陈旧文件清理。"""

from pathlib import Path
from typing import Dict, List, Tuple

from . import render_amis, render_py, render_tests
from .schema import ResourceSpec, load_specs

SITE = "amis/pages/site.json"
WIRING = {
    "app/models/__init__.py": "app.generated.models",
    "app/api/resources/__init__.py": "app.generated.resources",
}
#: 生成器拥有的目录/文件模式（陈旧文件清理只会动带标记的文件）
OWNED_GLOBS = ["app/generated/models/*.py", "app/generated/resources/*.py", "tests/generated/*.py", "amis/pages/*-list.json"]


def compute(root: Path, specs: Dict[str, ResourceSpec]) -> Dict[str, str]:
    """返回 ``{相对路径: 内容}``。同一份规格输入，输出逐字节相同。"""
    out: Dict[str, str] = {
        "app/generated/__init__.py": render_py.render_package_init(),
        "app/generated/permissions.py": render_py.render_permissions(specs),
        "app/generated/models/__init__.py": render_py.render_models_init(specs),
        "app/generated/resources/__init__.py": render_py.render_resources_init(specs),
    }
    for r in sorted(specs):
        s = specs[r]
        out[f"app/generated/models/{r}.py"] = render_py.render_model(s, specs)
        out[f"app/generated/resources/{r}.py"] = render_py.render_resource(s, specs)
        out[f"amis/pages/{r}-list.json"] = render_amis.render_page(s, specs)
        out[f"tests/generated/test_gen_{r}.py"] = render_tests.render_test(s, specs)
    site = root / SITE
    out[SITE] = render_amis.merge_site(site.read_text(encoding="utf-8"), specs)
    return out


def stale_files(root: Path, wanted: Dict[str, str]) -> List[str]:
    stale = []
    for pattern in OWNED_GLOBS:
        for p in sorted(root.glob(pattern)):
            rel = p.relative_to(root).as_posix()
            if rel not in wanted and render_py.MARK in p.read_text(encoding="utf-8"):
                stale.append(rel)
    if (root / "tests/generated").is_dir():
        pass
    return stale


def wiring_problems(root: Path) -> List[str]:
    return [
        f"{f} 缺少接线（应导入 {needle}）"
        for f, needle in WIRING.items()
        if needle not in (root / f).read_text(encoding="utf-8")
    ]


def diff(root: Path, wanted: Dict[str, str]) -> Tuple[List[str], List[str]]:
    """返回 (内容不一致/缺失的文件, 陈旧文件)。"""
    changed = []
    for rel, content in wanted.items():
        p = root / rel
        if not p.exists() or p.read_bytes() != content.encode("utf-8"):
            changed.append(rel)
    return changed, stale_files(root, wanted)


def run(root: Path, spec_dir: Path, check: bool = False) -> Tuple[List[str], List[str]]:
    specs = load_specs(spec_dir, spec_dir.relative_to(root).as_posix() if spec_dir.is_relative_to(root) else spec_dir.name)
    wanted = compute(root, specs)
    changed, stale = diff(root, wanted)
    if check:
        return changed, stale
    for rel in changed:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(wanted[rel].encode("utf-8"))
    for rel in stale:
        (root / rel).unlink()
    return changed, stale
