#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
``TRUSTED_PROXIES`` 的环境变量接线（v0.4.3 / 缺陷 C3）。

背景
====
限流器（``app/auth/rate_limit.py``）早已支持「直连对端命中可信代理白名单时才
采信 ``X-Forwarded-For``」，但 ``app/config.py`` 里 ``TRUSTED_PROXIES`` 是写死的
空字符串——**部署在 nginx 之后没有任何办法打开它**，导致限流把所有用户算成
同一个来源（一个人输错口令会锁住整个出口 15 分钟）。

本项只补「接线」这一层配置读取；白名单的解析与门控逻辑已存在且有测试
（``tests/test_login_ratelimit.py`` 的两个门控用例），此处不重复。

为什么在子进程里测
==================
``app/config.py`` 在 import 阶段就构造配置对象并读环境变量。同进程内改
``os.environ`` 不会影响已经构造好的对象，也测不到「读环境变量的那条路径」。
所以用 ``subprocess`` 起干净进程，只 import 配置、打印该字段的值。

为什么用 testing 环境而不是 production
======================================
production 需要 ``JWT_PRIVATE_KEY`` 等密钥才能 import（fail-closed 设计）。
那套验签逻辑与「读环境变量连到配置字段」是两件事，混在一起测会让本文件
依赖密钥构造。这里用 testing 环境，**只验证接线本身**；production 下的
密钥 fail-closed 由 ``tests/test_production_failclosed.py`` 单独覆盖。

安全默认值
==========
默认必须是空字符串（只信 socket 直连）。若哪天有人把它改成 ``"0.0.0.0/0"``
之类的宽松默认，``test_default_is_empty`` 会红。
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

#: 子进程里跑的探测脚本：只 import 配置，打印 TRUSTED_PROXIES 的值
_PROBE = (
    "import sys;"
    "sys.path.insert(0, {root!r});"
    "from app.config import get_config;"
    "cfg = get_config();"
    "print('VALUE=' + (cfg.TRUSTED_PROXIES or ''))"
)

#: 会被父进程/夹具污染、且与本项无关的环境变量，先全部清掉
_ENV_TO_CLEAR = (
    "SANIC_ENV",
    "TRUSTED_PROXIES",
    "SECRET_KEY",
    "PASSWORD_SALT",
    "JWT_PRIVATE_KEY",
    "JWT_PUBLIC_KEY",
    "INITIAL_ADMIN_PASSWORD",
)


def _read_config(env_overrides: dict, timeout: int = 120) -> str:
    """在干净子进程里 import 配置，返回 ``TRUSTED_PROXIES`` 的实际值。"""
    env = dict(os.environ)
    for name in _ENV_TO_CLEAR:
        env.pop(name, None)
    env.update(env_overrides)

    result = subprocess.run(
        [sys.executable, "-c", _PROBE.format(root=str(REPO_ROOT))],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    assert result.returncode == 0, (
        f"子进程 import 配置失败：\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    for line in result.stdout.splitlines():
        if line.startswith("VALUE="):
            return line[len("VALUE="):]
    raise AssertionError(f"探测脚本没有输出 VALUE= 行：\n{result.stdout!r}")


def test_default_is_empty():
    """未设环境变量时必须是空字符串（只信 socket 直连）。"""
    value = _read_config({"SANIC_ENV": "testing"})
    assert value == "", (
        f"默认值必须为空（只信 socket 直连），实际 {value!r}——"
        "宽松默认会让客户端伪造 X-Forwarded-For 绕过登录限流"
    )


def test_env_var_is_read():
    """设了环境变量就能读到——这正是本项要修的那条断链。"""
    value = _read_config({"SANIC_ENV": "testing", "TRUSTED_PROXIES": "127.0.0.1"})
    assert value == "127.0.0.1", f"环境变量没被读到，实际 {value!r}"


def test_env_var_accepts_multiple_entries_and_cidr():
    """逗号分隔的多个条目原样透传（拆分与 CIDR 解析在限流器侧，已另有测试）。"""
    raw = "127.0.0.1,10.0.0.0/8"
    value = _read_config({"SANIC_ENV": "testing", "TRUSTED_PROXIES": raw})
    assert value == raw, f"多条目被改写，实际 {value!r}"


@pytest.mark.parametrize("env_name", ["development", "testing"])
def test_env_var_read_in_non_production_envs(env_name):
    """两个非生产环境（development / testing）都能读到。"""
    value = _read_config({"SANIC_ENV": env_name, "TRUSTED_PROXIES": "10.0.0.0/8"})
    assert value == "10.0.0.0/8", f"{env_name} 下环境变量没生效，实际 {value!r}"
