#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
`python -m tools.specgen migrate` 的端到端测试。

这组用例守的是一个**主线缺陷**（#11 合入时漏带了 `tools/specgen/migrations.py`
与 `cli.py` 的 migrate 子命令）：master 曾处于「`check_migrations` 会红、却没有任何
工具能修」的死胡同——改了规格、模型变了，只能手写迁移。

核心对照（CPL 指定）：
  给规格加一个字段 -> `check_migrations` 退出码 1
  -> 执行 `specgen migrate`
  -> `check_migrations` 退出码 0，且三种方言的增量都已生成
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from tools.specgen import migrations as mig  # noqa: E402

PYTHON = sys.executable
CHECK_SCRIPT = REPO / "scripts" / "check_migrations.py"


def _env() -> dict:
    env = dict(os.environ)
    env.update({
        "SANIC_ENV": "development",
        "INITIAL_ADMIN_PASSWORD": "Mig-Test-Initial-Pass-1",
    })
    # 子进程必须只从 sandbox 导入。仓库根若在 PYTHONPATH 里，`app.models`
    # 会解析到仓库那份（旧模型），导致「加了字段却 check 仍绿」的假象。
    env.pop("PYTHONPATH", None)
    return env


def _run(args, cwd, timeout=300):
    env = _env()
    # 确保子进程优先从 cwd 解析包（`-m tools.specgen` 与 `app.models` 都是）
    env["PYTHONPATH"] = str(cwd)
    return subprocess.run(
        [PYTHON, *args], capture_output=True, text=True,
        timeout=timeout, cwd=str(cwd), env=env)


def _check_exit(repo_root: Path) -> int:
    """
    在 **sandbox 自己的** check_migrations 副本上跑，返回真实退出码。

    不能直接用仓库里的 scripts/check_migrations.py：它用
    `REPO = Path(__file__).parent.parent` 定位仓库，并 `sys.path.insert` 让
    `app.models` 从那里导入——传别的迁移目录只会换迁移侧，模型侧仍是**真实仓库**
    的旧模型，于是「加了字段」看起来毫无变化（退出码 0），整个对照空转。
    必须跑 sandbox 里的副本，两侧才都指向 sandbox。
    """
    script = repo_root / "scripts" / "check_migrations.py"
    if not script.is_file():
        raise AssertionError(f"sandbox 里没有 check_migrations.py：{script}")
    return _run([str(script), str(repo_root / "migrations")], repo_root).returncode


@pytest.fixture()
def sandbox(tmp_path):
    """
    把生成器与迁移链复制到临时仓库根，测试只改副本。

    只复制必需部分：`tools/specgen`、`scripts/`、`specs/`、`migrations/`，
    以及 `app/`（check_migrations 要导入 app.models 与生成的模型）。
    """
    for rel in ("tools", "scripts", "specs", "migrations", "app", "amis"):
        src = REPO / rel
        if src.exists():
            shutil.copytree(src, tmp_path / rel,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    # 干净起点：不带上跑测试残留的 __pycache__
    return tmp_path


# ---------------------------------------------------------------------------
# 前提：migrate 子命令必须存在
# ---------------------------------------------------------------------------


def test_migrate_subcommand_is_registered():
    """`specgen migrate` 必须是被认可的子命令（#11 遗漏时这里是坏的）。"""
    result = _run(["-m", "tools.specgen", "--help"], REPO)
    assert result.returncode == 0, result.stderr[-500:]
    assert "migrate" in result.stdout, (
        "specgen 的 CLI 里没有 migrate 子命令——"
        "#11 遗漏 tools/specgen/migrations.py 与 cli.py 的该子命令")


def test_migrations_module_importable():
    """`tools.specgen.migrations` 必须可导入，且暴露三方言常量。"""
    assert mig.DIALECTS == ("sqlite", "mysql", "postgres")


# ---------------------------------------------------------------------------
# 核心对照：加字段 -> check 红 -> migrate -> check 绿
# ---------------------------------------------------------------------------


def test_new_field_makes_check_fail_then_migrate_fixes_it(sandbox):
    """
    CPL 指定的主对照：
      1. 给 customer 规格加一个字段 -> check_migrations 退出码 1
      2. 执行 specgen generate + migrate
      3. check_migrations 退出码 0
      4. 三种方言都产出了新迁移
    """
    # --- 前提：干净起点是绿的 ---
    assert _check_exit(sandbox) == 0, "沙箱初始状态应一致，否则对照不成立"

    # --- 1. 加字段 ---
    spec = sandbox / "specs" / "customer.yaml"
    original = spec.read_text(encoding="utf-8")
    spec.write_text(
        original.replace("  - name: notes", "  - name: vip_level\n    type: int\n    label: 会员等级\n  - name: notes"),
        encoding="utf-8")
    assert spec.read_text(encoding="utf-8") != original, "规格替换未生效，对照不成立"

    gen = _run(["-m", "tools.specgen", "generate"], sandbox)
    assert gen.returncode == 0, f"generate 失败：{gen.stderr[-500:]}"

    # --- 2. 模型变了但迁移没跟上 -> 必须红 ---
    assert _check_exit(sandbox) == 1, (
        "加了字段却没生成迁移时，check_migrations 必须返回 1")

    # --- 3. migrate ---
    before = {
        d: {p.name for p in (sandbox / "migrations" / "dialects" / d).glob("*.py")}
        for d in mig.DIALECTS
    }
    result = _run(["-m", "tools.specgen", "migrate"], sandbox)
    assert result.returncode == 0, f"migrate 失败：{result.stderr[-800:]}"

    # --- 4. 三种方言都新增了同一个文件名 ---
    after = {
        d: {p.name for p in (sandbox / "migrations" / "dialects" / d).glob("*.py")}
        for d in mig.DIALECTS
    }
    added = {d: after[d] - before[d] for d in mig.DIALECTS}
    for d in mig.DIALECTS:
        assert added[d], f"{d} 没有产出新迁移"
    names = {d: sorted(v)[0] for d, v in added.items()}
    assert len(set(names.values())) == 1, (
        f"三方言的迁移文件名必须一致（aerich 以文件名作账本版本键）：{names}")

    # --- 5. check 恢复绿 ---
    assert _check_exit(sandbox) == 0, "migrate 之后 check_migrations 必须回到 0"


def test_migrate_generates_add_column_not_full_table(sandbox):
    """
    加字段应产出 `ALTER TABLE ... ADD`，而不是重建整张表。

    重建会丢数据；这条守住「增量」的语义。
    """
    spec = sandbox / "specs" / "customer.yaml"
    spec.write_text(
        spec.read_text(encoding="utf-8").replace(
            "  - name: notes", "  - name: vip_level\n    type: int\n    label: 会员等级\n  - name: notes"),
        encoding="utf-8")
    assert _run(["-m", "tools.specgen", "generate"], sandbox).returncode == 0

    before = {p.name for p in (sandbox / "migrations" / "dialects" / "sqlite").glob("*.py")}
    assert _run(["-m", "tools.specgen", "migrate"], sandbox).returncode == 0
    new = [
        p for p in (sandbox / "migrations" / "dialects" / "sqlite").glob("*.py")
        if p.name not in before
    ]
    assert len(new) == 1, f"应恰好新增一个迁移，实际 {[p.name for p in new]}"

    text = new[0].read_text(encoding="utf-8")
    assert "ADD" in text.upper(), "加字段的迁移应包含 ALTER TABLE ... ADD"
    assert "vip_level" in text, "迁移里应提到新字段"
    # 只加列，不该重建 customer 表
    assert "CREATE TABLE" not in text, (
        "加字段不应重建整表（会丢数据），实际生成的迁移里出现了 CREATE TABLE")


def test_migrate_is_noop_when_consistent(sandbox):
    """迁移链已覆盖模型时，migrate 不产出空迁移。"""
    before = {
        d: {p.name for p in (sandbox / "migrations" / "dialects" / d).glob("*.py")}
        for d in mig.DIALECTS
    }
    result = _run(["-m", "tools.specgen", "migrate"], sandbox)
    assert result.returncode == 0, result.stderr[-500:]
    after = {
        d: {p.name for p in (sandbox / "migrations" / "dialects" / d).glob("*.py")}
        for d in mig.DIALECTS
    }
    assert before == after, "一致时不应产出新迁移"
    assert "无需新迁移" in result.stdout or "无需" in result.stdout, result.stdout[-300:]


# ---------------------------------------------------------------------------
# 正向对照：check 真的会因缺迁移而红（否则上面的对照是空转）
# ---------------------------------------------------------------------------


def test_check_fails_when_increment_removed(sandbox):
    """
    正向对照：把增量迁移拿掉（等价于「模型领先于迁移链」），check 必须红。

    没有这条，上面 test_new_field_makes_check_fail_then_migrate_fixes_it 里
    的「退出码 1」可能只是别的原因恰好返回 1。
    """
    # 取每个方言当前的最大版本号（不写死 2_*，master 上增量起始序号可能不同）
    removed = []
    for d in mig.DIALECTS:
        files = sorted(
            (p for p in (sandbox / "migrations" / "dialects" / d).glob("*.py")
             if not p.name.startswith("0_")),
            key=lambda p: mig._version_num(p.name))
        assert files, f"{d} 没有增量迁移可供移除，前提不成立"
        newest = files[-1]
        newest.unlink()
        removed.append(newest.name)
        for p in (sandbox / "migrations" / "models").glob(newest.name):
            p.unlink()
    assert removed, "没有增量可供移除，前提不成立"

    assert _check_exit(sandbox) == 1, "缺增量迁移时 check_migrations 必须返回 1"
