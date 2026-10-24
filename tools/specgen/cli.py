# -*- coding: utf-8 -*-
"""命令行入口：``python -m tools.specgen {generate|check|validate}``。"""

import argparse
import sys
from pathlib import Path

from . import generate
from .schema import SpecError, load_specs

ROOT = Path(__file__).resolve().parent.parent.parent


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="specgen", description="规格即代码生成器")
    ap.add_argument(
        "command",
        choices=["generate", "check", "validate"],
        help="generate 写盘；check 只检查漂移（CI 用）；validate 只校验规格",
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
