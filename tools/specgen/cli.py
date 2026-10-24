# -*- coding: utf-8 -*-
"""命令行入口：``python -m tools.specgen {generate|check|validate}``。"""

import argparse
import sys
from pathlib import Path

from . import generate
from .schema import SpecError, load_specs

ROOT = Path(__file__).resolve().parent.parent.parent


def _migrate(root: Path) -> int:
    """为生成模型的结构变化产出三方言迁移。"""
    from . import migrations as mig

    try:
        result = mig.generate(root)
    except mig.MigrationPlanError as exc:
        print(f"需要人工迁移：\n{exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # 渲染/解析失败都必须报错，不能静默当作「无变化」
        print(f"迁移生成失败：{exc!r}", file=sys.stderr)
        return 2
    changed = {d: p for d, p in result.items() if p}
    if not changed:
        print("OK: 迁移链已覆盖当前模型，无需新迁移")
        return 0
    for d, p in changed.items():
        print(f"写入 {p}  ({d})")
    print(f"完成：{len(changed)} 份方言迁移")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="specgen", description="规格即代码生成器")
    ap.add_argument(
        "command",
        choices=["generate", "check", "validate", "migrate"],
        help=(
            "generate 写盘；check 只检查漂移（CI 用）；validate 只校验规格；"
            "migrate 为生成模型的结构变化产出三方言迁移"
        ),
    )
    ap.add_argument("--root", type=Path, default=ROOT, help="项目根目录")
    ap.add_argument("--specs", type=Path, default=None, help="规格目录，默认 <root>/specs")
    args = ap.parse_args(argv)
    root = args.root.resolve()
    spec_dir = (args.specs or root / "specs").resolve()
    try:
        if args.command == "validate":
            specs = load_specs(spec_dir, "specs")
            print(f"OK: {len(specs)} 份规格合法 ({', '.join(sorted(specs))})")
            return 0
        if args.command == "migrate":
            return _migrate(root)
        problems = generate.wiring_problems(root)
        if problems:
            print("\n".join(problems), file=sys.stderr)
            return 2
        changed, stale = generate.run(root, spec_dir, check=args.command == "check")
    except SpecError as exc:
        print(f"规格错误:\n{exc}", file=sys.stderr)
        return 1
    if args.command == "check":
        for rel in changed:
            print(f"DRIFT {rel}")
        for rel in stale:
            print(f"STALE {rel}")
        if changed or stale:
            print("生成物与规格不一致：运行 python -m tools.specgen generate", file=sys.stderr)
            return 1
        print("OK: 生成物与规格一致")
        return 0
    for rel in changed:
        print(f"写入 {rel}")
    for rel in stale:
        print(f"删除 {rel}")
    print(f"完成：{len(changed)} 个文件更新，{len(stale)} 个陈旧文件清理")
    return 0
