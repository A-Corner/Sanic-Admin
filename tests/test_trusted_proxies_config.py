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


# ----------------------------------------------------------------------
# 非法值：配置层必须拦，不能静默透传
# ----------------------------------------------------------------------
#
# 为什么这组用例必须存在（EVT-20261028-023-REVIEW finding 1 + 2）
# ==============================================================
# 消费方 ``LoginRateLimiter._addr_trusted`` 对每条 entry 是
# ``except ValueError: continue``——非法条目被**静默跳过**。配置层若也裸透传，
# 运维把 ``TRUSTED_PROXIES`` 写错（空格代替斜杠、前缀长度超范围、纯文本）时：
# 启动无提示 → 白名单实际为空 → XFF 恒不采信 → 本项要修的缺陷无感知复现。
#
# 所以规则是：
#   * production  —— 拒绝启动（ConfigError），报错写明**哪一条**、原值是什么
#   * 非 production —— warning 后跳过非法条目，保留合法条目继续跑
#
# 这组用例同时钉住「配置层真的会解析」这件事：如果哪天有人把校验退回成裸
# ``os.getenv``，下面的用例会红。


#: 各类非法输入。每一项都应该在 production 下拒绝启动。
INVALID_ENTRIES = [
    pytest.param("10.0.0.0/33", id="cidr-prefix-out-of-range"),
    pytest.param("not-an-ip", id="plain-text"),
    pytest.param("10.0.0.0 255.0.0.0", id="netmask-space-form"),
    pytest.param("999.1.1.1", id="octet-out-of-range"),
    pytest.param("10.0.0.0/8,oops", id="valid-then-invalid"),
]


def _run_config_probe(env_overrides: dict, timeout: int = 120):
    """
    在干净子进程里 ``get_config()``，返回 (returncode, stdout, stderr)。

    与 ``_read_config`` 的区别：这个**允许非零退出**——production 拒绝启动
    正是被测行为，不能因为 ``returncode != 0`` 就断言失败。
    """
    env = dict(os.environ)
    for name in _ENV_TO_CLEAR:
        env.pop(name, None)
    env.update(env_overrides)
    # production 需要这两个才能走到 TRUSTED_PROXIES 校验之后（见 app/config.py 顶部）
    env.setdefault("JWT_PRIVATE_KEY", "")
    env.setdefault("INITIAL_ADMIN_PASSWORD", "")

    result = subprocess.run(
        [sys.executable, "-c", _PROBE.format(root=str(REPO_ROOT))],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


@pytest.mark.parametrize("bad_entry", INVALID_ENTRIES)
def test_production_rejects_invalid_entry(bad_entry):
    """
    production 下非法条目必须**拒绝启动**，且报错写明是哪一条。

    不是「警告后继续」——安全配置静默降级等于没配，运维不会发现。
    """
    code, out, err = _run_config_probe(
        {"SANIC_ENV": "production", "TRUSTED_PROXIES": bad_entry}
    )
    assert code != 0, (
        f"production 下 TRUSTED_PROXIES={bad_entry!r} 应当拒绝启动，实际退出码 {code}。\n"
        f"stdout={out!r}\nstderr={err!r}"
    )
    combined = out + err
    assert "TRUSTED_PROXIES" in combined, (
        f"拒绝信息里必须点名 TRUSTED_PROXIES，实际输出：{combined!r}"
    )
    # 报错要能定位到具体是哪一条——只写「配置非法」运维还是不知道该改哪
    first_token = bad_entry.split(",")[0].strip()
    assert first_token in combined, (
        f"拒绝信息里必须包含出错的条目原文 {first_token!r}，实际输出：{combined!r}"
    )


@pytest.mark.parametrize("bad_entry", INVALID_ENTRIES)
def test_non_production_warns_and_skips_invalid_entry(bad_entry):
    """
    非 production 下非法条目只 warning，合法条目仍生效，进程继续启动。

    本地开发不该因为一条写错就起不来；但也不能静默——必须有 warning。
    """
    code, out, err = _run_config_probe(
        {"SANIC_ENV": "testing", "TRUSTED_PROXIES": f"127.0.0.1,{bad_entry}"}
    )
    assert code == 0, (
        f"非 production 下非法条目不应阻止启动，实际退出码 {code}。\nstderr={err!r}"
    )
    assert "TRUSTED_PROXIES" in out + err, (
        f"非 production 下必须给出 warning，实际没有：{out + err!r}"
    )
    # 合法条目必须被保留下来（不是整串丢弃）
    assert "VALUE=127.0.0.1" in out, (
        f"合法条目应被保留，实际输出：{out!r}"
    )


def test_empty_entries_are_rejected_in_production():
    """
    空条目（连续逗号 / 尾部逗号）在 production 下也算配置错误。

    理由：``"10.0.0.0/8,"`` 这种写法几乎总是手误（多打一个逗号，或本想写第二
    个网段但忘了填）。消费方会静默丢掉空段看不出问题，配置层若也放过，
    下一次手误写掉一整条网段同样不会有任何提示。
    """
    code, out, err = _run_config_probe(
        {"SANIC_ENV": "production", "TRUSTED_PROXIES": "10.0.0.0/8,,127.0.0.1"}
    )
    assert code != 0, f"production 下空条目应拒绝启动，实际退出码 {code}"
    assert "TRUSTED_PROXIES" in out + err


def test_valid_entries_are_normalized():
    """
    合法条目会被规范化成标准形式（``ipaddress`` 解析后回写）。

    这不是「顺手做的美化」：规范化保证了下游 ``_addr_trusted`` 拿到的 entry
    一定是可解析的，否则它会在 ``except ValueError: continue`` 里静默跳过。
    顺带把 ``10.0.0.1/8`` 这种「网段里写了主机位」的常见写法收敛成 ``10.0.0.0/8``。
    """
    value = _read_config(
        {"SANIC_ENV": "testing", "TRUSTED_PROXIES": " 10.0.0.1/8 , 127.0.0.1 "}
    )
    assert value == "10.0.0.0/8,127.0.0.1", f"条目未规范化，实际 {value!r}"
