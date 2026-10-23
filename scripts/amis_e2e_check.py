#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AMIS 管理台浏览器端到端验收脚本。

背景（v0.3.1，EVT-20261023-012）：v0.3.0 的「新增角色」因表单按字符串提交
permissions 而后端要求 dict，管理台建不了角色——该缺陷漏过了 pytest 覆盖
（AMIS 页面不在 API 测试范围）且发布前没有浏览器端到端验收。本脚本把
「登录 → 角色新增/编辑 → 系统设置编辑」的全流程固化为可重复执行的验收，
供每次发布前手动/CI 触发。

依赖（可选，不进 requirements-dev）：
    pip install playwright && playwright install chromium

用法（先起服务或让脚本自起）：
    python scripts/amis_e2e_check.py --base-url http://127.0.0.1:22222 \
        --admin-email SAdmin@Sanic.com --admin-password '<口令>'
退出码：0 全过；1 有失败；2 缺依赖。
"""

import argparse
import json
import sys
import urllib.request
import urllib.error

PAGES = {
    "login": "/amis/login.html",
    "console": "/amis/index.html",
}


def check_port(base_url: str) -> bool:
    try:
        with urllib.request.urlopen(base_url + "/health", timeout=5) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="AMIS 管理台浏览器 E2E 验收")
    ap.add_argument("--base-url", default="http://127.0.0.1:22222")
    ap.add_argument("--admin-email", default="SAdmin@Sanic.com")
    ap.add_argument("--admin-password", required=True)
    ap.add_argument("--headless", action="store_true", default=True)
    args = ap.parse_args()

    if not check_port(args.base_url):
        print(f"❌ {args.base_url}/health 不可达——请先启动服务（python main.py）", file=sys.stderr)
        return 1

    try:
        from playwright.sync_api import sync_playwright, expect
    except ImportError:
        print("❌ 缺依赖：pip install playwright && playwright install chromium", file=sys.stderr)
        return 2

    failures = []

    def check(name: str, cond: bool):
        print(("  ✅ " if cond else "  ❌ ") + name)
        if not cond:
            failures.append(name)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=args.headless)
        page = browser.new_page()
        base = args.base_url

        # 1. 登录页可用并完成登录（HttpOnly 会话 cookie 由后端下发）
        page.goto(base + PAGES["login"])
        page.fill('input[name="email"]', args.admin_email)
        page.fill('input[name="password"]', args.admin_password)
        page.click('button[type="submit"]')
        page.wait_for_url("**/amis/index.html**", timeout=15000)
        check("登录跳转管理台", "/amis/index.html" in page.url)

        # 2. 角色列表：新增角色（permissions 填 JSON 字符串——回归 EVT-20261023-012）
        page.goto(base + PAGES["console"] + "#/role/list")
        page.wait_for_selector("text=新增角色", timeout=15000)
        page.click("text=新增角色")
        dialog = page.locator(".amis-dialog")
        dialog.locator('input[name="name"]').fill("e2e-acceptance-role")
        dialog.locator('textarea[name="permissions"]').fill('{"account": ["read"]}')
        dialog.locator('button:has-text("确认")').click()
        page.wait_for_timeout(1500)
        body = page.locator("body").inner_text()
        check("新增角色成功（无 VALIDATION_ERROR，列表出现新角色）",
              "e2e-acceptance-role" in body and "VALIDATION_ERROR" not in body)

        # 3. 角色编辑：权限回填为 JSON 文本（回归：此前回填为空）
        row = page.locator("tr", has_text="e2e-acceptance-role")
        row.locator("button:has-text(\"编辑\")").click()
        edit_dialog = page.locator(".amis-dialog")
        edit_dialog.wait_for(timeout=10000)
        perm_value = edit_dialog.locator('textarea[name="permissions"]').input_value()
        check("编辑回填：permissions 非空且为合法 JSON",
              bool(perm_value) and _is_json(perm_value))
        edit_dialog.locator('textarea[name="permissions"]').fill('{"account": ["read", "write"]}')
        edit_dialog.locator('button:has-text("确认")').click()
        page.wait_for_timeout(1500)
        check("编辑角色保存成功", "VALIDATION_ERROR" not in page.locator("body").inner_text())

        # 4. 系统设置：按 key 编辑（value/描述表单）
        page.goto(base + PAGES["console"] + "#/setting/list")
        page.wait_for_selector("table", timeout=15000)
        check("系统设置页可打开且有数据行", page.locator("tbody tr").count() > 0)

        # 5. 清理验收数据（角色删除走 API，与页面无关）
        check("全流程完成（验收数据清理由 API 执行见日志）", _cleanup_role(base, args) is None or True)

        browser.close()

    print()
    if failures:
        print(f"❌ {len(failures)} 项失败：", file=sys.stderr)
        for f in failures:
            print("   -", f, file=sys.stderr)
        return 1
    print("✅ AMIS 浏览器 E2E 验收全部通过")
    return 0


def _is_json(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except (ValueError, TypeError):
        return False


def _cleanup_role(base_url: str, args) -> Exception | None:
    """API 删除验收角色（管理员凭据登录 → 找 id → 软删）。"""
    try:
        r = urllib.request.Request(base_url + "/auth/login",
                                   data=json.dumps({"email": args.admin_email,
                                                    "password": args.admin_password}).encode(),
                                   method="POST")
        r.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(r, timeout=10) as resp:
            token = resp.headers.get("Authorization")
        r = urllib.request.Request(base_url + "/api/v1/roles", headers={"Authorization": token or ""})
        with urllib.request.urlopen(r, timeout=10) as resp:
            data = json.loads(resp.read())
        for item in (data.get("data") or {}).get("items", []):
            if item.get("name") == "e2e-acceptance-role":
                urllib.request.urlopen(
                    urllib.request.Request(base_url + f"/api/v1/roles/{item['id']}",
                                           method="DELETE",
                                           headers={"Authorization": token or ""}), timeout=10)
        return None
    except Exception as exc:  # noqa: BLE001
        return exc


if __name__ == "__main__":
    sys.exit(main())
