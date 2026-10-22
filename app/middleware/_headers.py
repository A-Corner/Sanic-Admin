# -*- coding: utf-8 -*-
"""响应头辅助函数。"""


def append_vary(headers, value: str) -> None:
    """向 Vary 头合并追加 value（不覆盖已有值，不重复）。"""
    existing = headers.get('Vary')
    if not existing:
        headers['Vary'] = value
        return
    tokens = [t.strip() for t in existing.split(',') if t.strip()]
    if '*' in tokens or value.lower() in (t.lower() for t in tokens):
        return
    headers['Vary'] = ', '.join(tokens + [value])
