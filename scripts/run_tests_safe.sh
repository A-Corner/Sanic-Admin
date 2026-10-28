#!/usr/bin/env bash
# 测试入口包装：强制临时产物落在仓库外，否则拒绝运行。
#
# 为什么需要：pytest 默认把临时目录放在系统 TMPDIR（内盘），一次全量测试
# 可产生数百 MB。内盘空间紧张，且这些产物不应出现在仓库或系统临时区。
#
# 本脚本不含任何本机绝对路径——所需路径全部从环境变量读取，因此可以安全地
# 进入公开仓库。本地约定值放在 `.git/info/exclude` 里的 env 脚本中（不公开）。
#
# 用法：
#   export PYTHON_BIN=/path/to/venv/bin/python   # 必填，必须与 requirements 一致
#   source .git/info/exclude.d/test-env.sh      # 设置 TMPDIR / PYTEST_BASETEMP
#   scripts/run_tests_safe.sh [pytest 参数...]  # 可从任意 cwd 调用
#
# PYTHON_BIN 必须显式设置，脚本不回退到 .venv 或 PATH（EVT-20261028-027/031）。
# 理由：静默回退可能落到版本不符合 requirements.txt 的解释器上，测试照常跑完
# 并给出结果，但那个结果不可信（例如 sanic-routing 23.6.0 会把 405 静默转成
# 404，让「本该失败的 404 断言」假绿）。
#
# 启动时始终打印解释器的**实际路径与实际版本**，并**逐包校验 requirements.txt
# 中全部 == 钉版**：任一不符即 exit 2。校验列表从 requirements.txt 动态解析，
# 脚本内不出现任何包名或版本号（新增/调整钉版无需改本脚本）。
#
# pattern 类参数的边界约束见 delete 端点；本脚本不涉及。
#
# 退出码：
#   0  测试通过
#   1  测试失败
#   2  环境不合规（外挂盘未挂载 / 路径指向内盘 / 变量未设置 /
#      requirements.txt 缺失或未钉版 / PYTHON_BIN 未设置 / 不可执行 /
#      不是 Python / 版本与钉版不符）——测试未运行

set -euo pipefail

fail() {
    echo "❌ $*" >&2
    exit 2
}

# --- 1. 变量必须设置 ---------------------------------------------------------
: "${TMPDIR:?TMPDIR 未设置。请先 source 本地 env 脚本（见脚本头注释）}"
: "${PYTEST_BASETEMP:?PYTEST_BASETEMP 未设置。请先 source 本地 env 脚本}"

# --- 2. 目录必须可创建、可写（先建再用 df 判断，df 对不存在的路径会失败）-----
mkdir -p "$PYTEST_BASETEMP" 2>/dev/null \
    || fail "无法创建 ${PYTEST_BASETEMP}（外挂盘是否已挂载？）"
[ -w "$PYTEST_BASETEMP" ] || fail "${PYTEST_BASETEMP} 不可写"
mkdir -p "$TMPDIR" 2>/dev/null || fail "无法创建 TMPDIR=${TMPDIR}"
[ -w "$TMPDIR" ] || fail "TMPDIR=${TMPDIR} 不可写"

# --- 3. 挂载点检查：必须位于独立的挂载点（外挂卷），不能在内盘 ----------------
#
# 为什么不用「挂载点 == /」：macOS 上内盘的数据卷挂载在 /System/Volumes/Data，
# /tmp、/Users 都在它下面，挂载点**不是** /。用 == / 判断会漏掉整个内盘。
#
# 可靠判据：比较**设备**。目标路径的设备不能与根文件系统（/）的设备相同族。
# 更简单且跨平台的等价判据：挂载点必须是一个显式的卷挂载点。
#
# **本脚本只支持 macOS**：白名单写死 /Volumes/*（见下面 case 分支）。
# Linux 的 /mnt、/media 不在白名单内，在 Linux 上运行会以 exit 2 拒绝——
# 这是有意为之，不是遗漏：本项目的测试与构建都在 macOS 的外挂卷上跑，
# 加一条没被真实使用过的 Linux 分支等于增加一条没人验证的代码路径。
# 将来若真要在 Linux 上跑，再连同验证一起加，不要先加分支后补验证。
check_external() {
    local path="$1" label="$2" mount dev root_dev
    mount="$(df -P "$path" | awk 'NR==2 {print $NF}')"
    [ -n "$mount" ] || fail "无法确定 ${label}=${path} 的挂载点"
    dev="$(df -P "$path" | awk 'NR==2 {print $1}')"
    root_dev="$(df -P / | awk 'NR==2 {print $1}')"

    # 与根设备相同 → 明确是内盘
    if [ "$dev" = "$root_dev" ]; then
        fail "拒绝运行：${label}=${path} 与根文件系统同设备（内盘）。
        测试产物不得落在内盘。"
    fi
    # 白名单：必须位于显式的卷挂载点下。**仅 macOS 的 /Volumes/<name>**。
    # 这比「排除 /System/Volumes/*」更稳——不依赖 macOS 具体把数据卷挂在哪，
    # 系统升级改了路径也不会静默失效（2026-10-28 首次实现用「挂载点==/」，
    # 在 macOS 上被判据漏掉，靠反向对照才发现）。
    #
    # 不含 Linux 的 /mnt、/media：见上方注释，Linux 未经验证故不支持。
    case "$mount" in
        /Volumes/*) : ;;
        *) fail "拒绝运行：${label}=${path} 的挂载点是 ${mount}，不在 /Volumes/ 下。
            本脚本仅支持 macOS（产物只能放在外挂卷 /Volumes/<name>）；
            Linux 的 /mnt、/media 未经验证，不在白名单内。" ;;
    esac
    echo "$mount"
}

MOUNT_POINT="$(check_external "$PYTEST_BASETEMP" PYTEST_BASETEMP)"
TMP_MOUNT="$(check_external "$TMPDIR" TMPDIR)"

# --- 6. Python 解释器：必须显式指定（PYTHON_BIN），不回退 --------------------
#
# 不回退到 .venv 或 PATH（031 裁定）：静默回退可能落到版本不符合 requirements
# 的解释器上，测试照跑、甚至全绿，但结论不可信（如 sanic-routing 23.6 会把
# 405 静默转 404）。也不要以为「下一层的哨兵校验能兜住」——哨兵只能挡
# 「不是 Python」的误配，挡不住「是 Python 但版本不对」的假绿。
[ -n "${PYTHON_BIN:-}" ] || fail "PYTHON_BIN 未设置。拒绝回退到 .venv 或 PATH——
     静默回退会得到一个不可信的绿。请显式指向满足 requirements.txt 的 venv：
       export PYTHON_BIN=/path/to/venv/bin/python"

if [ ! -x "$PYTHON_BIN" ]; then
    fail "PYTHON_BIN 指向的路径不可执行：${PYTHON_BIN}
     （该值来自环境变量 PYTHON_BIN，本脚本不会回退到其它解释器）
     请检查 .git/info/exclude.d/test-env.sh 里的配置是否指向了已删除的 venv，
     或把 PYTHON_BIN 改成现有的解释器路径。"
fi
PY="$PYTHON_BIN"

# 实际版本：路径对但版本错时脚本照跑、测试甚至可能过，结论却无效。
# 所以不只打印路径，必须把实际版本一并暴露出来。
#
# 「能运行」必须用哨兵字符串校验，不能只看退出码：一个误配的
# `#!/bin/sh; exit 0` 也会返回 0。只有真的输出了 __PYOK__ 才算 Python。
#
# **威胁模型（如实声明，不要让人以为这是安全边界）**：哨兵挡的是**误配**
# ——指向了脚本或非 Python 可执行文件。它**挡不住恶意替换**：
# `#!/bin/sh; echo __PYOK__; exit 0` 仍能通过本检查。这不是安全边界，
# 是配置错误检测。
# 注意：消息里的变量引用必须用 ${out} 花括号形式，不能用 $out ——
# 实测（实验 3 第一次跑）：$out 后面紧跟全角括号「）」时，bash 在 UTF-8
# locale 下会把多字节首字节并入变量名，报 `out: unbound variable`（set -u）。
# 半角括号则正常。凡变量后紧跟非 ASCII 字符，一律用 ${} 界定边界。
out="$("$PY" -c 'print("__PYOK__")' 2>/dev/null)" || \
    fail "解释器存在但无法运行：${PY}
     退出码非 0（输出：${out}）"
[ "${out}" = "__PYOK__" ] || fail "PYTHON_BIN 未产生预期输出（${out}），可能不是 Python：${PY}"

# 实际版本打印：放在哨兵校验之后 —— 「是 Python」确认过了，「什么版本」才有意义。
PY_VERSION="$(
    "$PY" -c 'import sys; print("Python " + sys.version.split()[0])' 2>/dev/null
)"

# --- 6b. 定位仓库根（不依赖调用者 cwd）--------------------------------------
#
# 用 BASH_SOURCE 而非 git rev-parse --show-toplevel：后者要求 cwd 在 git 仓库内
# （实测 cd /tmp 后直接报「不是 git 仓库」），而本脚本必须能从任意目录调用。
# 在 worktree 内两种做法结果相同（都得到 worktree 根），故无需引入 git 依赖。
_src="${BASH_SOURCE[0]}"
while [ -h "$_src" ]; do
    _dir="$(cd -P "$(dirname "$_src")" && pwd)"
    _src="$(readlink "$_src")"
    case "$_src" in /*) ;; *) _src="${_dir}/${_src}" ;; esac
done
REPO_ROOT="$(cd -P "$(dirname "$_src")/.." && pwd)"
REQ="${REPO_ROOT}/requirements.txt"

# --- 6c. requirements.txt 必须存在且含 == 钉版，否则无法校验版本 --------------
[ -f "$REQ" ] || fail "找不到 ${REQ}。
     当前工作副本（REPO_ROOT=${REPO_ROOT}）缺 requirements.txt；不回退到其他仓库的
     requirements——那会让「跑这棵树」与「校验那棵树」不一致。"

# 解析钉版：先剥离行尾 '# 注释' 与 '; 环境标记'（剥离而非整行跳过，避免带标记的
# 钉版包被静默漏检）；字符类必须含大写、数字、下划线、点、连字符，否则会漏掉
# 「含大写字母 / 数字 / 点 / 连字符」的发行包名——这类名字在主流包里很常见，
# 字符类写窄了会静默漏检。
#
# `|| true` 不可省（实测）：grep 无匹配返回 1，set -e + pipefail 会让脚本在
# **没有任何提示**的情况下 exit 1。这会让「requirements 未钉版」退化成静默失败，
# 与「不得静默降级」直接冲突。
PINS="$(sed -E 's/[[:space:]]*#.*$//; s/[[:space:]]*;.*$//' "$REQ" \
    | grep -E '^[A-Za-z0-9_.-]+==' || true)"
[ -n "$PINS" ] || fail "${REQ} 中没有任何 == 钉版依赖，无法校验解释器版本。
     本门禁只校验 == 钉版；若文件被改成全是 >= 约束，属配置异常。"

# --- 6d. 解释器版本必须与 requirements.txt 的 == 钉版一致 ---------------------
# 逐包比对（当前 6 个钉版），任一不符即 fail。>= 的包不校验（无唯一正确值）。
#
# 为什么用 heredoc 内嵌 Python 一次批量查，而不是 Bash 循环里逐包调 "$PY" -c：
# 6 个包各起一次解释器 = 6 次进程启动；批量查询整段 < 0.1s。且内嵌脚本能区分
# 「未安装」（PackageNotFoundError）、「查询失败」（其他异常）、「版本不符」三种状态。
#
# 为什么用 importlib.metadata.version() 而不是 import <mod>; <mod>.__version__：
# 有的发行包不暴露 __version__，用后者会漏检这个钉版包；且发行包名 ≠ import 名
# （两者存在系统性差异，需要维护映射表，新增依赖时忘配就漏检），用发行包名与
# requirements.txt 写法完全一致，零映射。
#
# flush=True 是硬性要求（实测踩到）：stdout 被管道/捕获时 Python 块缓冲会让
# ✓/✗ 行滞后到进程退出才输出，与 stderr 的 ❌ 顺序错乱。
_pins=()
while IFS= read -r _line; do
    [ -n "$_line" ] || continue
    _pins+=("${_line%%==*}=${_line#*==}")
done <<< "$PINS"

"$PY" - "${_pins[@]}" <<'PYEOF' || fail "解释器版本与 ${REQ} 不一致（逐包对比见上）"
import sys
from importlib.metadata import version, PackageNotFoundError

bad = 0
for spec in sys.argv[1:]:
    name, _, want = spec.rpartition("=")
    try:
        got = version(name)
    except PackageNotFoundError:
        print(f"  ✗ {name}: 期望 {want} / 未安装（该发行包不存在）", flush=True)
        bad += 1
        continue
    except Exception as exc:
        print(f"  ✗ {name}: 期望 {want} / 查询失败 {type(exc).__name__}: {exc}", flush=True)
        bad += 1
        continue
    if got == want:
        print(f"  ✓ {name}: {got}", flush=True)
    else:
        print(f"  ✗ {name}: 期望 {want} / 实际 {got}", flush=True)
        bad += 1

if bad:
    print(f"解释器版本不合规：{bad}/{len(sys.argv) - 1} 个钉版包不符", file=sys.stderr)
    sys.exit(1)
PYEOF
echo "✅            requirements.txt 钉版全部匹配（${#_pins[@]} 个包）"

echo "✅ 环境合规：TMPDIR=${TMPDIR}（挂载点 ${TMP_MOUNT}）"
echo "✅            basetemp=${PYTEST_BASETEMP}（挂载点 ${MOUNT_POINT}）"
echo "✅            REPO_ROOT=${REPO_ROOT}"
echo "✅            python=${PY}  (${PY_VERSION})"

# --- 7. 执行 ----------------------------------------------------------------
exec "$PY" -m pytest --basetemp="$PYTEST_BASETEMP" "$@"
