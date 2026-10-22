#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
production 环境缺密钥 → 拒绝启动（fail-closed）。

覆盖 CPL 验收口径第 9 项。

实现要点
========
这些用例必须**在子进程里跑**：``app/config.py`` 在 import 阶段就会构造当前环境的
配置对象，production 缺密钥时直接抛 ``ConfigError``。同进程内测不了（import 已经发生），
所以用 ``subprocess`` 起一个干净的 Python 进程，断言**退出码非 0** 且 stderr 有明确拒绝信息。

production 必需的密钥（见 ``app/config.py`` 顶部文档）：
* ``JWT_PRIVATE_KEY``（或 ``JWT_PUBLIC_KEY``）——RS256 PEM
* ``INITIAL_ADMIN_PASSWORD``——初始管理员口令

``SECRET_KEY`` / ``PASSWORD_SALT`` 在 M1 已降为可选（当前实现里不参与签名与口令哈希），
所以**不**拿它们当 fail-closed 的触发条件——那样断言的是旧契约。
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

#: production 下必须提供的环境变量
REQUIRED_PRODUCTION_VARS = ("JWT_PRIVATE_KEY", "INITIAL_ADMIN_PASSWORD")

#: 子进程里跑的探测脚本：只 import 配置，不启动服务
_PROBE = (
    "import sys;"
    "sys.path.insert(0, {root!r});"
    "import app.config as c;"
    "print('CONFIG_OK')"
)


def _run_probe(env_overrides: dict, timeout: int = 120):
    """
    在子进程里 import ``app.config``。

    Returns:
        ``subprocess.CompletedProcess``
    """
    env = dict(os.environ)
    # 清掉可能来自父进程（含 conftest）的全部生产相关变量
    for name in (
        "SANIC_ENV",
        "SECRET_KEY",
        "PASSWORD_SALT",
        "JWT_PRIVATE_KEY",
        "JWT_PUBLIC_KEY",
        "INITIAL_ADMIN_PASSWORD",
        "INITIAL_ADMIN_EMAIL",
        "INITIAL_ADMIN_USERNAME",
    ):
        env.pop(name, None)
    env.update(env_overrides)

    return subprocess.run(
        [sys.executable, "-c", _PROBE.format(root=str(REPO_ROOT))],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def test_production_without_secrets_refuses_to_start():
    """
    production 且完全不给密钥 → 退出码非 0，stderr 明确说明缺什么。

    这是 fail-closed 的核心断言：**缺配置时必须拒绝启动**，不能带着临时密钥跑起来。

    注意：配置是在 import 阶段构造的，遇到**第一个**缺失的必需变量就抛
    ``ConfigError``，所以报错信息只会点名那一个变量。逐项覆盖交给下面
    ``test_production_missing_single_required_secret_refuses_to_start``。
    """
    result = _run_probe({"SANIC_ENV": "production"})

    assert result.returncode != 0, (
        "production 缺少密钥时进程居然正常退出了（rc=0），这是 fail-open：\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )

    combined = result.stdout + result.stderr
    # 拒绝信息必须点名至少一个缺失的必需变量
    assert any(
        name in combined for name in REQUIRED_PRODUCTION_VARS
    ), f"拒绝信息里没有点名任何缺失的必需变量：\n{combined}"
    # 并且要说清楚是"生产环境必须提供"这件事
    assert "生产环境" in combined, f"拒绝信息没有说明是生产环境的强制要求：\n{combined}"


@pytest.mark.parametrize("missing_var", REQUIRED_PRODUCTION_VARS)
def test_production_missing_single_required_secret_refuses_to_start(missing_var):
    """
    只缺一个必需变量（另一个已提供）→ 仍然拒绝启动。

    用一个临时生成的 RSA 私钥满足 ``JWT_PRIVATE_KEY``，再单独抽掉另一个变量，
    确认 fail-closed 是**逐项**生效的，而不是"凑巧两个都缺才报错"。
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()

    env = {
        "SANIC_ENV": "production",
        "JWT_PRIVATE_KEY": private_pem,
        "INITIAL_ADMIN_PASSWORD": "ProductionAdminPass123!",
    }
    env.pop(missing_var, None)

    result = _run_probe(env)

    assert result.returncode != 0, (
        f"production 缺 {missing_var} 时仍然正常退出（rc=0），fail-closed 未生效：\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    combined = result.stdout + result.stderr
    assert missing_var in combined, (
        f"拒绝信息里没有点名缺失的变量 {missing_var}：\n{combined}"
    )


def test_production_with_all_secrets_configured_succeeds():
    """
    反向对照：production 把必需变量都给了 → import 成功。

    没有这条对照，"永远失败"也能让上一个用例通过。
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()

    result = _run_probe(
        {
            "SANIC_ENV": "production",
            "JWT_PRIVATE_KEY": private_pem,
            "INITIAL_ADMIN_PASSWORD": "ProductionAdminPass123!",
        }
    )

    assert result.returncode == 0, (
        f"production 配齐密钥后仍然启动失败：\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    assert "CONFIG_OK" in result.stdout


def test_development_without_secrets_still_starts():
    """
    development 缺密钥 → 仍能启动（生成临时值并 warning）。

    与 production 形成对照：fail-closed 只作用于生产环境，不阻塞本地开发。
    """
    result = _run_probe({"SANIC_ENV": "development"})

    assert result.returncode == 0, (
        f"development 缺密钥时启动失败：\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    assert "CONFIG_OK" in result.stdout


def test_main_entrypoint_exits_nonzero_in_production_without_secrets():
    """
    直接跑 ``main.py`` → 退出码非 0。

    ``main.py`` 捕获 ``ConfigError`` 后调用 ``sys.exit(...)``，所以退出码是 1。
    这条断言覆盖的是"入口真的拒绝启动"，而不只是"配置模块抛异常"。
    """
    env = dict(os.environ)
    for name in (
        "SANIC_ENV",
        "SECRET_KEY",
        "PASSWORD_SALT",
        "JWT_PRIVATE_KEY",
        "JWT_PUBLIC_KEY",
        "INITIAL_ADMIN_PASSWORD",
        "INITIAL_ADMIN_EMAIL",
    ):
        env.pop(name, None)
    env["SANIC_ENV"] = "production"

    result = subprocess.run(
        [sys.executable, "main.py"],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode != 0, (
        f"production 缺密钥时 main.py 居然退出码 0：\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    combined = result.stdout + result.stderr
    assert "配置错误" in combined or "ConfigError" in combined, (
        f"main.py 的拒绝信息不明确：\n{combined}"
    )
