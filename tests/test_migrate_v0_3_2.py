#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
v0.3.2 存量库迁移脚本的自动化测试（EVT-20261023-014 复审 Low 跟进 1）。

覆盖三点：
1. 脚本可重复执行（幂等）——连跑两遍，第二遍不重复 ALTER、退出码 0；
2. 历史默认口令能比对出来——v0.3.1 及更早版本硬编码的 SAdmin@123；
3. 管理员邮箱已改过时跳过创建——库里有管理员但无 INITIAL_ADMIN_EMAIL
   对应账户（且未加 --create-initial-admin）时不静默多建。

全部在临时 SQLite 上以子进程方式跑真实脚本（不是 import 后调用内部函数），
保证测的是交付给用户的那个入口。
"""

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "migrate_v0_3_2_must_change_password.py"


def _legacy_hash(raw_password: str) -> str:
    """按旧版本的方式生成口令哈希，**有意绕过**新版的口令策略校验。

    这些测试构造的是「v0.3.1 已经写进库里」的行——历史默认口令 SAdmin@123
    正是被迁移脚本要识别出来的目标。若这里改走 ``Account.set_password()``，
    L1 新增的弱口令拒绝清单会在**造数据阶段**就把 SAdmin@123 拦下，测试
    测的就不再是迁移脚本，而是口令策略本身。
    """
    from app.models.account import password_hasher

    return password_hasher.hash(raw_password)

#: 历史默认管理员口令（v0.3.1 及更早版本硬编码）
LEGACY_DEFAULT_PASSWORD = "SAdmin@123"

#: v0.3.1 形态的 account 表（无 must_change_password 列）
LEGACY_SCHEMA = """
CREATE TABLE account (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted BOOLEAN NOT NULL DEFAULT 0,
    username VARCHAR(32) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    phone VARCHAR(14),
    first_name VARCHAR(64),
    last_name VARCHAR(64),
    password VARCHAR(255) NOT NULL,
    disabled BOOL NOT NULL DEFAULT 0,
    verified BOOL NOT NULL DEFAULT 0,
    is_admin BOOL NOT NULL DEFAULT 0
)
"""


def _run_script(db_path: Path, admin_password: str, admin_email: str,
                *extra_args: str) -> subprocess.CompletedProcess:
    """以子进程跑真实脚本（与用户执行方式一致）。"""
    env = dict(os.environ)
    env.update({
        "SANIC_ENV": "testing",
        "DB_URL": f"sqlite://{db_path}",
        "INITIAL_ADMIN_PASSWORD": admin_password,
        "INITIAL_ADMIN_EMAIL": admin_email,
    })
    return subprocess.run(
        [sys.executable, str(SCRIPT), *extra_args],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=180,
    )


def _make_legacy_db(db_path: Path, *, email: str, password: str,
                    is_admin: bool = True, disabled: bool = False) -> None:
    """造一个 v0.3.1 形态的库（无新列）并插入一个管理员。"""
    from app.models import Account

    conn = sqlite3.connect(db_path)
    conn.execute(LEGACY_SCHEMA)
    account = Account(username="legacy", email=email, verified=True,
                      disabled=disabled, is_admin=is_admin)
    account.password = _legacy_hash(password)
    conn.execute(
        "INSERT INTO account (username, email, password, verified, disabled, is_admin) "
        "VALUES (?,?,?,?,?,?)",
        ("legacy", email, account.password, 1, int(disabled), int(is_admin)),
    )
    conn.commit()
    conn.close()


def _has_column(db_path: Path, column: str) -> bool:
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("PRAGMA table_info(account)").fetchall()
        return any(row[1] == column for row in rows)
    finally:
        conn.close()


def _flag_of(db_path: Path, email: str):
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT must_change_password FROM account WHERE email = ?", (email,)
        ).fetchone()
        return None if row is None else row[0]
    finally:
        conn.close()


def test_script_is_idempotent(tmp_path):
    """连跑两遍：第一遍补列/建表，第二遍跳过 ALTER，两次都 exit 0。"""
    db = tmp_path / "idem.db"

    first = _run_script(db, "MigPass2026!", "mig@test.local")
    assert first.returncode == 0, first.stderr
    assert "must_change_password" in first.stdout or "✅" in first.stdout
    assert _has_column(db, "must_change_password"), "第一遍后应存在新列"

    second = _run_script(db, "MigPass2026!", "mig@test.local")
    assert second.returncode == 0, second.stderr
    assert "已存在" in second.stdout or "跳过" in second.stdout, (
        f"第二遍应跳过 ALTER，实际输出：{second.stdout}"
    )
    assert _has_column(db, "must_change_password")


def test_legacy_default_password_is_flagged(tmp_path):
    """历史默认口令 SAdmin@123 的管理员：比对成功后置 must_change_password=True。"""
    db = tmp_path / "legacy_pw.db"
    _make_legacy_db(db, email="legacy@test.local", password=LEGACY_DEFAULT_PASSWORD)
    assert not _has_column(db, "must_change_password"), "前置：库应为 v0.3.1 形态"

    # 当前环境变量口令故意不同于历史默认口令——只有比对历史口令才能命中
    result = _run_script(db, "CompletelyDifferent2026!", "other@test.local")
    assert result.returncode == 0, result.stderr
    assert _has_column(db, "must_change_password")
    assert _flag_of(db, "legacy@test.local") == 1, (
        "口令仍为历史默认 SAdmin@123 的管理员必须被置强制改密"
    )


def test_legacy_password_does_not_leak_to_output(tmp_path):
    """脚本不打印、不记录任何口令（含历史默认口令）。"""
    db = tmp_path / "no_leak.db"
    _make_legacy_db(db, email="legacy@test.local", password=LEGACY_DEFAULT_PASSWORD)
    result = _run_script(db, "AnotherPass2026!", "other@test.local")
    combined = result.stdout + result.stderr
    assert LEGACY_DEFAULT_PASSWORD not in combined
    assert "AnotherPass2026!" not in combined


def test_changed_admin_email_skips_creation(tmp_path):
    """管理员邮箱已改过（有管理员但无 INITIAL_ADMIN_EMAIL 账户）：警告并跳过创建。"""
    db = tmp_path / "changed_email.db"
    _make_legacy_db(db, email="renamed-admin@test.local", password="SomePass2026!")

    result = _run_script(db, "MigPass2026!", "original@test.local")
    assert result.returncode == 0, result.stderr
    # 警告走 stderr（脚本用 file=sys.stderr 输出，避免与正常进度混流）
    combined = result.stdout + result.stderr
    assert "跳过" in combined, f"应提示跳过创建，实际输出：{combined}"
    conn = sqlite3.connect(db)
    try:
        emails = {row[0] for row in conn.execute("SELECT email FROM account")}
    finally:
        conn.close()
    assert "original@test.local" not in emails, "不应静默多建一个管理员"
    assert "renamed-admin@test.local" in emails, "原有管理员应保留"


def test_create_initial_admin_flag_forces_creation(tmp_path):
    """--create-initial-admin 可强制创建（正向对照：证明上面的跳过不是「永远不建」）。"""
    db = tmp_path / "forced.db"
    _make_legacy_db(db, email="renamed-admin@test.local", password="SomePass2026!")

    result = _run_script(db, "MigPass2026!", "original@test.local",
                         "--create-initial-admin")
    assert result.returncode == 0, result.stderr
    conn = sqlite3.connect(db)
    try:
        emails = {row[0] for row in conn.execute("SELECT email FROM account")}
    finally:
        conn.close()
    assert "original@test.local" in emails, "带开关时应创建初始管理员"


def test_disabled_and_non_admin_not_flagged(tmp_path):
    """边界：被禁用的管理员与非管理员即使口令是默认值也不置标志。"""
    db = tmp_path / "boundary.db"
    conn = sqlite3.connect(db)
    conn.execute(LEGACY_SCHEMA)
    from app.models import Account

    rows = [
        ("disabled_admin", "disabled-admin@test.local", True, True),
        ("normal_user", "normal@test.local", False, False),
    ]
    for username, email, is_admin, disabled in rows:
        account = Account(username=username, email=email, verified=True,
                          disabled=disabled, is_admin=is_admin)
        account.password = _legacy_hash(LEGACY_DEFAULT_PASSWORD)
        conn.execute(
            "INSERT INTO account (username, email, password, verified, disabled, is_admin) "
            "VALUES (?,?,?,?,?,?)",
            (username, email, account.password, 1, int(disabled), int(is_admin)),
        )
    conn.commit()
    conn.close()

    result = _run_script(db, "DifferentAdminPass2026!", "other@test.local")
    assert result.returncode == 0, result.stderr
    assert _has_column(db, "must_change_password")
    assert _flag_of(db, "disabled-admin@test.local") == 0, "被禁用的管理员不比对"
    assert _flag_of(db, "normal@test.local") == 0, "非管理员不比对"
