#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""`app.config._bool_env` 的严格解析契约。

为什么需要这组测试（`EVT-20261029-009`）：

`EVT-20261028-040` 裁定「不把 `app/__init__.py` 里的 `bool(...)` 换成严格解析」，
理由是**正规路径已经严格**——`ALLOW_NOOP_DELIVERY` 的唯一读入点
`app/config.py:465` 走 `_bool_env`，它白名单精确匹配、非法值抛 `ConfigError`。

但该属性此前**没有任何测试锁住**：`grep -rn '_bool_env\\|必须为布尔值\\|garbage' tests/`
零命中。也就是说 040 的裁定前提是「代码正确」而非「被回归守住」——日后有人把
`_bool_env` 改成静默回退（例如 `raw.lower() in ("true", "1")` 这种常见写法），
现有测试不会变红，而 040 的裁定就会在无人察觉的情况下变成错的。

本文件的判据就是那条前提：**非法值必须抛异常，不能静默回退成 False**。
破坏实验（把 `raise ConfigError` 改成 `return default`）：下面的 `test_rejects_*`
会用例全红。
"""

import pytest

from app.config import _FALSE_VALUES, _TRUE_VALUES, ConfigError, _bool_env


@pytest.mark.parametrize("raw", ["1", "true", "TRUE", "yes", "on", " true ", "\ttrue\n"])
def test_truthy_values(monkeypatch, raw):
    """白名单内的真值（含大小写与首尾空白）解析为 True。"""
    monkeypatch.setenv("PROBE_BOOL", raw)
    assert _bool_env("PROBE_BOOL", False) is True


@pytest.mark.parametrize("raw", ["0", "false", "FALSE", "no", "off", "", "   "])
def test_falsy_values(monkeypatch, raw):
    """白名单内的假值（含空串与纯空白）解析为 False。"""
    monkeypatch.setenv("PROBE_BOOL", raw)
    assert _bool_env("PROBE_BOOL", True) is False


def test_unset_returns_default(monkeypatch):
    """未设置时返回调用方给的默认值，而不是硬编码 False。"""
    monkeypatch.delenv("PROBE_BOOL", raising=False)
    assert _bool_env("PROBE_BOOL", True) is True
    assert _bool_env("PROBE_BOOL", False) is False


@pytest.mark.parametrize(
    "raw",
    [
        "garbage",  # 完全无法识别
        "y",  # 常见缩写：**故意不接受**，避免与 "yes" 语义分歧
        "n",
        "2",  # 数字但不在白名单
        "tru",  # 拼写不完整
        "false ",  # 这个其实合法（strip 后是 false）——见下方对照
    ],
)
def test_rejects_non_whitelisted_values(monkeypatch, raw):
    """白名单之外的值一律抛 ConfigError，**不静默回退**。

    这是 040 裁定成立的核心前提：如果这里退化成 `return default`，
    `ALLOW_NOOP_DELIVERY=garbage` 会被当作「没开」而静默放行，
    生产环境的投递后端缺失就会从「启动即失败」变成「运行期才发现」。
    """
    monkeypatch.setenv("PROBE_BOOL", raw)
    if raw == "false ":
        # 对照：尾部空白的合法值不该抛（strip 生效）——
        # 这条保证了上面的「拒绝」不是因为实现粗暴地拒绝了所有带空格的输入。
        assert _bool_env("PROBE_BOOL", True) is False
        return
    with pytest.raises(ConfigError) as exc:
        _bool_env("PROBE_BOOL", False)
    assert "PROBE_BOOL" in str(exc.value)
    assert "必须为布尔值" in str(exc.value)


def test_error_message_includes_raw_value(monkeypatch):
    """报错必须带出原始值，否则运维不知道该改哪个拼写。"""
    monkeypatch.setenv("PROBE_BOOL", "TrUe!")
    with pytest.raises(ConfigError) as exc:
        _bool_env("PROBE_BOOL", False)
    assert "'TrUe!'" in str(exc.value)


def test_true_and_false_lists_are_disjoint():
    """两个白名单不相交——否则同一个值既是真又是假，结果取决于判断顺序。"""
    assert not (set(_TRUE_VALUES) & set(_FALSE_VALUES))


def test_bool_builtin_would_have_been_wrong(monkeypatch):
    """正向对照：证明这组测试测的是 `_bool_env`，不是 `bool()`。

    `bool("false") == True`——如果实现退化成 `bool(os.getenv(var))`，
    上面所有 falsy 用例都会红，而这条断言说明「为什么不能用 bool()」。
    """
    assert bool("false") is True
    assert bool("0") is True
    assert bool("off") is True
    # 而 _bool_env 对同样的输入给出相反答案：
    monkeypatch.setenv("PROBE_BOOL", "false")
    assert _bool_env("PROBE_BOOL", True) is False
