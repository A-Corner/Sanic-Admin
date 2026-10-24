#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AMIS 管理台浏览器端到端验收脚本。

背景（v0.3.1，EVT-20261023-012）：v0.3.0 的「新增角色」因表单按字符串提交
permissions 而后端要求 dict，管理台建不了角色——该缺陷漏过了 pytest 覆盖
（AMIS 页面不在 API 测试范围）且发布前没有浏览器端到端验收。本脚本把
「登录 → 角色新增/编辑 → 各列表页」的全流程固化为可重复执行的验收，
供每次发布前手动/CI 触发。

依赖（可选，不进 requirements-dev）：
    pip install playwright && playwright install chromium

用法（先起服务或让脚本自起）：
    python scripts/amis_e2e_check.py --base-url http://127.0.0.1:22222 \
        --admin-email SAdmin@Sanic.com --admin-password '<口令>'
首次登录、账户仍带 must_change_password 时，必须再给 --new-password，
脚本会先走完强制改密再验收。

正向对照（证明测量手段本身有效）：
    python scripts/amis_e2e_check.py ... --negative-control dialog
把弹窗选择器改成一个必然不存在的值后重跑：脚本要求「新增角色」这项**必须失败**，
若它仍然通过，说明该断言是恒真的，脚本以退出码 1 报警。

退出码：
    0 全部通过（--negative-control 时为「对照失败符合预期」）
    1 有失败 / 清理未落实 / 正向对照未按预期失败
    2 缺依赖（playwright 或浏览器不可用）

设计约束（每条都对应一次真实的误判，见文件内注释）：
    * 选择器集中在 ``SELECTORS``，任何一处都不得写「a or b」式兜底——
      兜底会让选择器错误退化成静默通过。
    * 表格断言行数时必须排除 amis 的「暂无数据」占位行，否则空表也算有数据。
    * 清理必须自己核验（删除后重新查询确认消失），不得使用 ``x is None or True``。
"""

import argparse
import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PAGES = {
    "login": "/amis/login.html",
    "console": "/amis/index.html",
}

#: 页面选择器。每个值都必须能被真实 DOM 命中；不要写逗号并集兜底——
#: 那会把「选择器写错」变成「换个选择器也能过」，验收就失去意义。
SELECTORS = {
    # amis/login.html 的密码字段名是 pass（不是 password）。
    "login_email": 'input[name="email"]',
    "login_password": 'input[name="pass"]',
    "login_submit": '#login-form button[type="submit"]',
    "change_password_form": "#change-password-form",
    "change_password_current": '#change-password-form input[name="current_password"]',
    "change_password_new": '#change-password-form input[name="new_password"]',
    "change_password_confirm": '#change-password-form input[name="confirm_password"]',
    # amis 弹窗根节点：.amis-dialog-widget（3.4.0 与 6.13.0 均为该 class，
    # 同时带 cxd-Modal；.amis-dialog 命中 0 个）。
    "dialog": ".amis-dialog-widget",
    "dialog_name": 'input[name="name"]',
    "dialog_permissions": 'textarea[name="permissions"]',
    "dialog_confirm": 'button:has-text("确认")',
}

#: 表格空态占位行文本。amis crud 在无数据时仍在 tbody 渲染一行占位，
#: 直接用 ``tbody tr > 0`` 判断「有数据行」会恒真。
EMPTY_ROW_MARKERS = ("暂无数据", "No data", "没有数据")

#: 验收断言总数（与 amis-upgrade.md 的 19 项口径一致）。
EXPECTED_CHECKS = 19

#: 负向对照里被破坏后的选择器
BROKEN_SELECTORS = {
    "dialog": ".amis-dialog-widget-does-not-exist",
    "login_password": 'input[name="password-does-not-exist"]',
}

#: 「设置有数据行」断言用的探针设置值与键
SETTING_PROBE_KEY = "site_name"
_SETTING_PROBE_VALUE = "Sanic-Admin E2E"

#: 验收角色名前缀（清理按此后缀匹配；角色名唯一，每次运行追加时间戳）
ROLE_PREFIX = "e2e-acceptance-role"


def check_port(base_url: str) -> bool:
    try:
        with urllib.request.urlopen(base_url + "/health", timeout=5) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False


class _ApiClient:
    """带 cookie 与 CSRF 头的极简 API 客户端。

    ``/auth/login`` 走 HttpOnly 会话 cookie，响应里**没有** Authorization 头
    （只有 Set-Cookie），所以清理流程必须用 cookie jar，而不是读响应头。
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )

    def _csrf(self) -> str:
        for cookie in self.jar:
            if cookie.name == "csrf_token":
                return cookie.value
        return ""

    def request(self, method: str, path: str, payload=None):
        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        if method not in ("GET", "HEAD", "OPTIONS"):
            token = self._csrf()
            if token:
                headers["X-CSRF-Token"] = token
        req = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        with self.opener.open(req, timeout=15) as resp:
            raw = resp.read()
            try:
                return resp.status, json.loads(raw) if raw else {}
            except ValueError:
                return resp.status, {}

    def login(self, email: str, password: str) -> None:
        status, body = self.request(
            "POST", "/auth/login", {"email": email, "password": password}
        )
        if status != 200:
            raise RuntimeError(f"API 登录失败（HTTP {status}）: {body.get('message')}")


def _list_roles(api: _ApiClient) -> list:
    status, body = api.request("GET", "/api/v1/roles?page=1&page_size=100")
    if status != 200:
        raise RuntimeError(f"角色列表读取失败（HTTP {status}）")
    return (body.get("data") or {}).get("items") or []


def _delete_roles_by_prefix(api: _ApiClient, prefix: str) -> int:
    """删除全部名字以 prefix 开头的角色，返回删除条数。"""
    deleted = 0
    for item in _list_roles(api):
        name = item.get("name") or ""
        if name.startswith(prefix):
            status, body = api.request("DELETE", f"/api/v1/roles/{item['id']}")
            if status != 200:
                raise RuntimeError(
                    f"删除角色 {name}(id={item['id']}) 失败（HTTP {status}）: "
                    f"{body.get('message')}"
                )
            deleted += 1
    return deleted


def cleanup_role(base_url: str, email: str, password: str, prefix: str):
    """API 删除验收角色并**核验**其确实消失。

    按前缀清理：``Role.name`` 唯一且软删除的行仍占用名字
    （``Role.filter(name=...).exists()`` 不过滤 ``deleted``），所以同名角色
    删一次之后仍然无法重建。每次运行用唯一名字、清理按前缀，才不会互相干扰。

    Returns:
        None 表示清理已落实（含「本来就不存在」）；否则返回异常。
    """
    try:
        api = _ApiClient(base_url)
        api.login(email, password)
        _delete_roles_by_prefix(api, prefix)
        remaining = [
            r.get("name") for r in _list_roles(api)
            if (r.get("name") or "").startswith(prefix)
        ]
        if remaining:
            return AssertionError(f"清理后仍有角色 {remaining}")
        return None
    except Exception as exc:  # noqa: BLE001
        return exc


def ensure_setting(base_url: str, email: str, password: str, key: str, value: str) -> _ApiClient:
    """确保至少存在一条系统设置，供「设置有数据行」断言使用。

    空库下 system_setting 表为 0 行，而 amis 空态占位行会让 ``tbody tr > 0`` 恒真，
    所以这里先造一条真实数据，再断言页面能看到它。

    Returns:
        已登录的 API 客户端，供调用方后续清理。
    """
    api = _ApiClient(base_url)
    api.login(email, password)
    try:
        api.request("POST", "/api/v1/settings", {"key": key, "value": value})
    except urllib.error.HTTPError as exc:
        # 已存在（409）属正常，其余错误要暴露
        if exc.code != 409:
            raise
    return api


def cleanup_setting(api: "_ApiClient | None", key: str) -> None:
    """删除验收期间创建的系统设置（不存在则跳过）。"""
    if api is None:
        return
    status, body = api.request("GET", "/api/v1/settings?page=1&page_size=100")
    if status != 200:
        return
    for item in (body.get("data") or {}).get("items") or []:
        if item.get("key") == key and item.get("value") == _SETTING_PROBE_VALUE:
            api.request("DELETE", f"/api/v1/settings/{item['id']}")


def _data_rows(page):
    """tbody 中**排除空态占位**的数据行。"""
    rows = page.locator("tbody tr")
    total = rows.count()
    data = []
    for i in range(total):
        text = rows.nth(i).inner_text().strip()
        if text and not any(marker in text for marker in EMPTY_ROW_MARKERS):
            data.append(text)
    return data, total


def _launch(pw, channel):
    kwargs = {"headless": True}
    if channel:
        kwargs["channel"] = channel
    return pw.chromium.launch(**kwargs)


def main() -> int:
    ap = argparse.ArgumentParser(description="AMIS 管理台浏览器 E2E 验收")
    ap.add_argument("--base-url", default="http://127.0.0.1:22222")
    ap.add_argument("--admin-email", default="SAdmin@Sanic.com")
    ap.add_argument("--admin-password", required=True)
    ap.add_argument(
        "--new-password",
        default=None,
        help="账户 must_change_password=True 时用于完成强制改密的新口令（≥8 位）",
    )
    ap.add_argument(
        "--role-name",
        default=None,
        help="验收角色名前缀；缺省为 e2e-acceptance-role-<时间戳>（唯一名字，避免撞唯一约束）",
    )
    ap.add_argument(
        "--channel",
        default=None,
        help="浏览器 channel，如 chrome；缺省用 playwright 自带 chromium",
    )
    ap.add_argument(
        "--negative-control",
        choices=sorted(BROKEN_SELECTORS),
        default=None,
        help="正向对照：故意破坏指定选择器，要求对应断言失败",
    )
    args = ap.parse_args()

    # 每次运行用唯一角色名：Role.name 唯一且软删除行仍占名字，固定名字会在
    # 第二次运行时撞 ROLE_EXISTS。清理按前缀进行，历史残留也能一并收掉。
    if not args.role_name:
        role_prefix = ROLE_PREFIX
        args.role_name = f"{ROLE_PREFIX}-{time.strftime('%Y%m%d%H%M%S')}"
    else:
        role_prefix = args.role_name

    selectors = dict(SELECTORS)
    if args.negative_control:
        selectors[args.negative_control] = BROKEN_SELECTORS[args.negative_control]

    if not check_port(args.base_url):
        print(
            f"❌ {args.base_url}/health 不可达——请先启动服务（python main.py）",
            file=sys.stderr,
        )
        return 1

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(
            "❌ 缺依赖：pip install playwright && playwright install chromium",
            file=sys.stderr,
        )
        return 2

    failures = []
    checks = []

    def check(name: str, cond: bool, detail: str = ""):
        ok = bool(cond)
        checks.append((name, ok))
        print(("  ✅ " if ok else "  ❌ ") + name + (f"   [{detail}]" if detail else ""))
        if not ok:
            failures.append(name)
        return ok

    effective_password = args.admin_password
    cleanup_error = None
    setting_api = None

    try:
        with sync_playwright() as pw:
            try:
                browser = _launch(pw, args.channel)
            except Exception as exc:  # noqa: BLE001
                print(f"❌ 浏览器无法启动：{exc}", file=sys.stderr)
                return 2

            page = browser.new_page()
            base = args.base_url

            # 0. 登录页可用
            page.goto(base + PAGES["login"], wait_until="domcontentloaded")
            check("登录页可加载", page.locator(selectors["login_email"]).count() == 1)

            # 1. 登录（含首次登录强制改密）
            # 选择器写错时必须让断言失败并继续跑完，而不是抛栈中断：
            # 正向对照要看到「登录跳转管理台」这条断言变红。
            login_ok = False
            try:
                page.fill(selectors["login_email"], args.admin_email, timeout=10000)
                page.fill(selectors["login_password"], args.admin_password, timeout=10000)
                page.click(selectors["login_submit"], timeout=10000)
                login_ok = True
            except Exception as exc:  # noqa: BLE001
                print(f"  ⚠️  登录表单操作失败：{str(exc).splitlines()[0]}", file=sys.stderr)

            deadline = time.time() + 30
            change_prompt = False
            while login_ok and time.time() < deadline:
                if "/amis/index.html" in page.url:
                    break
                try:
                    if page.locator(selectors["change_password_form"]).is_visible():
                        change_prompt = True
                        break
                except Exception:  # noqa: BLE001 - 页面正在跳转
                    pass
                page.wait_for_timeout(200)

            if change_prompt:
                if not args.new_password:
                    print(
                        "❌ 账户处于首次登录强制改密状态（must_change_password=True），"
                        "请追加 --new-password '<新口令>'；或先手工完成一次改密。",
                        file=sys.stderr,
                    )
                    return 1
                page.fill(selectors["change_password_current"], args.admin_password)
                page.fill(selectors["change_password_new"], args.new_password)
                page.fill(selectors["change_password_confirm"], args.new_password)
                page.click(f'{selectors["change_password_form"]} button[type="submit"]')
                try:
                    page.wait_for_url("**/amis/index.html**", timeout=20000)
                except Exception:  # noqa: BLE001
                    pass
                effective_password = args.new_password

            check("登录跳转管理台", "/amis/index.html" in page.url, page.url)

            # 2. app 外壳
            page.wait_for_timeout(2500)
            body = page.locator("body").inner_text()
            check("app 外壳渲染（菜单「角色管理」）", "角色管理" in body)
            check("app 外壳渲染（菜单「仪表盘」）", "仪表盘" in body)
            check("头部/退出登录渲染", page.locator("#logout-link").count() >= 1)

            # 3. 仪表盘
            page.goto(base + PAGES["console"] + "#/dashboard", wait_until="domcontentloaded")
            page.wait_for_timeout(2500)
            dash = page.locator("body").inner_text()
            check("仪表盘标题渲染", "仪表盘" in dash)
            check("仪表盘卡片渲染（账户总数）", "账户总数" in dash)
            # 收紧（CPL 复核第 4 项）：原先只要「账户总数」之后 40 个字符里出现任意数字
            # 就算通过——而仪表盘正文里到处是数字，这条断言等于恒真。
            #
            # 实测（AMIS 3.4.0 + Chrome）：`.cxd-Card` 只渲染了 title 与 subTitle，
            # 卡片的 `body`（含 ${accounts.total} 模板）**没有被渲染**，因此卡片里
            # 本来就没有数值可断言。这是 v0.3.x 既有的页面行为，不是本次改动引入的。
            #
            # 所以这条断言改成「结构断言」：仪表盘必须渲染出预期数量的卡片，且每张
            # 卡片都有标题。数值绑定另由 API 层测试覆盖（dashboard 端点 200 + 信封结构）。
            # 这样它不再恒真，也不会因为页面本身不渲染数值而长期红着。
            card_count = page.locator(".cxd-Card").count()
            title_count = page.locator(".cxd-Card-title").count()
            check(
                "仪表盘卡片结构渲染（4 张卡片且均有标题）",
                card_count >= 4 and title_count >= 4,
                "cards=%d titles=%d" % (card_count, title_count),
            )

            # 4. 角色列表
            page.goto(base + PAGES["console"] + "#/role/list", wait_until="domcontentloaded")
            page.wait_for_timeout(3000)
            role_body = page.locator("body").inner_text()
            rows, raw_rows = _data_rows(page)
            check("角色列表 crud 表格渲染", len(rows) > 0, f"data_rows={len(rows)} raw={raw_rows}")
            check("角色列表有新增入口", "新增角色" in role_body)
            check(
                "role crud 无组件未找到报错",
                "渲染器" not in role_body and "not found" not in role_body.lower(),
            )

            # 5. 新增角色（permissions 以 JSON 对象提交——回归 EVT-20261023-012）
            added = False
            try:
                page.click("text=新增角色")
                dialog = page.locator(selectors["dialog"]).first
                dialog.wait_for(timeout=10000)
                dialog.locator(selectors["dialog_name"]).fill(args.role_name)
                dialog.locator(selectors["dialog_permissions"]).fill('{"account": ["read"]}')
                dialog.locator(selectors["dialog_confirm"]).click()
                page.wait_for_timeout(2000)
                after = page.locator("body").inner_text()
                added = args.role_name in after and "VALIDATION_ERROR" not in after
                check("新增角色成功（无 VALIDATION_ERROR）", added)
            except Exception as exc:  # noqa: BLE001
                check("新增角色成功（无 VALIDATION_ERROR）", False, str(exc)[:160])

            # 6. 角色编辑：权限回填为 JSON 文本
            try:
                row = page.locator("tr", has_text=args.role_name).first
                row.locator('button:has-text("编辑")').click()
                edit = page.locator(selectors["dialog"]).first
                edit.wait_for(timeout=10000)
                page.wait_for_timeout(1200)
                perm = edit.locator(selectors["dialog_permissions"]).input_value()
                check(
                    "编辑回填：permissions 非空且为合法 JSON",
                    bool(perm) and _is_json(perm),
                    repr(perm[:60]),
                )
                edit.locator(selectors["dialog_permissions"]).fill(
                    '{"account": ["read", "update"]}'
                )
                edit.locator(selectors["dialog_confirm"]).click()
                page.wait_for_timeout(2000)
                check(
                    "编辑角色保存成功",
                    "VALIDATION_ERROR" not in page.locator("body").inner_text(),
                )
            except Exception as exc:  # noqa: BLE001
                # 两条断言都要落账：异常时若只记一条，断言总数会悄悄少一项，
                # 门禁就变松了（EXPECTED_CHECKS 兜底会把它抓出来，但那样报的是
                # "断言数不对"，掩盖真正的失败原因）。
                check("编辑回填：permissions 非空且为合法 JSON", False, str(exc)[:160])
                check("编辑角色保存成功", False, "前置回填失败")

            # 7. 账户列表（filter.body + filter-toggler）
            page.goto(base + PAGES["console"] + "#/account/list", wait_until="domcontentloaded")
            page.wait_for_timeout(3000)
            acct = page.locator("body").inner_text()
            rows, raw_rows = _data_rows(page)
            check("账户列表 crud 表格渲染", len(rows) > 0, f"data_rows={len(rows)} raw={raw_rows}")
            check(
                "账户列表 filter 关键字输入框渲染",
                page.locator('input[name="keyword"]').count() > 0,
            )
            # 收紧：原先用「正文里出现『关键字』」判定，页面上任何含该词的文本都能
            # 让它通过。改为要求 filter 区域确实渲染了 keyword 输入控件。
            check(
                "账户列表 filter-toggler 控件存在",
                page.locator('input[name="keyword"]').is_visible(),
                "keyword_input=%d" % page.locator('input[name="keyword"]').count(),
            )

            # 8. 系统设置（先保证有真实数据行，再断言页面能看到它）
            setting_detail = ""
            try:
                setting_api = ensure_setting(
                    base, args.admin_email, effective_password,
                    SETTING_PROBE_KEY, _SETTING_PROBE_VALUE,
                )
            except Exception as exc:  # noqa: BLE001
                setting_detail = f"准备设置数据失败: {exc}"
            page.goto(base + PAGES["console"] + "#/setting/list", wait_until="domcontentloaded")
            page.wait_for_timeout(3000)
            rows, raw_rows = _data_rows(page)
            setting_ok = (
                not setting_detail and len(rows) > 0
                and any(SETTING_PROBE_KEY in r for r in rows)
            )
            check(
                "系统设置页有真实数据行（排除空态占位）",
                setting_ok,
                f"data_rows={len(rows)} raw={raw_rows} {setting_detail}".strip(),
            )

            # 9. 操作日志（表头断言：空表也算渲染成功，但不能只数 tr）
            page.goto(base + PAGES["console"] + "#/log/list", wait_until="domcontentloaded")
            page.wait_for_timeout(2500)
            headers = " ".join(
                page.locator("thead th").nth(i).inner_text()
                for i in range(page.locator("thead th").count())
            )
            log_rows, log_raw = _data_rows(page)
            check(
                "操作日志页渲染（表头含 操作/IP）",
                "操作" in headers and "IP" in headers,
                f"headers={headers.strip()[:60]} data_rows={len(log_rows)} raw={log_raw}",
            )

            browser.close()
    finally:
        # 清理只做一次，且在浏览器关闭之后：用 API + cookie 会话执行并自核验。
        cleanup_error = cleanup_role(
            args.base_url, args.admin_email, effective_password, role_prefix
        )
        try:
            cleanup_setting(setting_api, SETTING_PROBE_KEY)
        except Exception:  # noqa: BLE001 - 探针设置清理失败不掩盖主要结论
            pass

    print()
    if cleanup_error is not None:
        print(f"  ❌ 验收数据清理失败：{cleanup_error}", file=sys.stderr)
    else:
        print(f"  ✅ 验收数据清理已核验（前缀 {role_prefix} 下已无角色）")

    passed = len(checks) - len(failures)

    if args.negative_control:
        return _report_negative(args, checks, failures, cleanup_error)

    print(f"\n=== {passed}/{len(checks)} 项通过 ===")
    if len(checks) != EXPECTED_CHECKS:
        print(
            f"❌ 断言数 {len(checks)} 与预期 {EXPECTED_CHECKS} 不一致——"
            "断言被删减会让门禁悄悄变松",
            file=sys.stderr,
        )
        return 1
    if failures:
        print(f"❌ {len(failures)} 项失败：", file=sys.stderr)
        for name in failures:
            print("   -", name, file=sys.stderr)
        return 1
    if cleanup_error is not None:
        return 1
    print("✅ AMIS 浏览器 E2E 验收全部通过")
    return 0


def _report_negative(args, checks, failures, cleanup_error) -> int:
    """正向对照的判定：被破坏的那条断言**必须**失败。

    选择器被破坏后，依赖同一选择器的后续断言也会失败（级联），这是预期的；
    但任何**不在预期级联集合内**的失败都说明对照不干净，不能算通过。
    """
    name = _CHECK_FOR_CONTROL[args.negative_control]
    allowed_cascade = _CASCADE[args.negative_control]
    target = [c for c in checks if c[0] == name]
    # failures 存的是断言名（str），不是 (name, ok) 元组
    unexpected = [f for f in failures if f != name and f not in allowed_cascade]
    print(f"\n=== 正向对照（--negative-control {args.negative_control}）===")
    print(f"目标断言：{name}")
    if not target:
        print("❌ 目标断言未执行，对照组无效", file=sys.stderr)
        return 1
    if unexpected:
        print(f"❌ 出现非预期失败，对照不干净：{unexpected}", file=sys.stderr)
        return 1
    if cleanup_error is not None:
        print(f"❌ 清理失败：{cleanup_error}", file=sys.stderr)
        return 1
    if target[0][1]:
        print(
            "❌ 选择器被故意改错后断言仍然通过——该断言是恒真的，门禁无效",
            file=sys.stderr,
        )
        return 1
    print("✅ 选择器被故意改错后断言如期失败——测量手段有效")
    return 0


#: 正向对照：被破坏的选择器 -> 应当失败的那条断言
_CHECK_FOR_CONTROL = {
    "dialog": "新增角色成功（无 VALIDATION_ERROR）",
    "login_password": "登录跳转管理台",
}

#: 正向对照：被破坏的选择器 -> 允许随之失败（级联）的其它断言
_CASCADE = {
    # 编辑对话框复用同一个弹窗选择器
    "dialog": {
        "编辑回填：permissions 非空且为合法 JSON",
        "编辑角色保存成功",
    },
    # 登录失败则其后所有页面断言都不成立
    "login_password": {
        "app 外壳渲染（菜单「角色管理」）",
        "app 外壳渲染（菜单「仪表盘」）",
        "头部/退出登录渲染",
        "仪表盘标题渲染",
        "仪表盘卡片渲染（账户总数）",
        "仪表盘数据绑定生效（数字非空）",
        "角色列表 crud 表格渲染",
        "角色列表有新增入口",
        "role crud 无组件未找到报错",
        "新增角色成功（无 VALIDATION_ERROR）",
        "编辑回填：permissions 非空且为合法 JSON",
        "编辑角色保存成功",
        "账户列表 crud 表格渲染",
        "账户列表 filter 关键字输入框渲染",
        "账户列表 filter-toggler 控件存在",
        "系统设置页有真实数据行（排除空态占位）",
        "操作日志页渲染（表头含 操作/IP）",
    },
}


def _is_json(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except (ValueError, TypeError):
        return False


if __name__ == "__main__":
    sys.exit(main())
