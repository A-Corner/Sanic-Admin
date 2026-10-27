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
#   source .git/info/exclude.d/test-env.sh   # 设置 TMPDIR / PYTEST_BASETEMP
#   scripts/run_tests_safe.sh [pytest 参数...]
#
# 退出码：
#   0  测试通过
#   1  测试失败
#   2  环境不合规（外挂盘未挂载 / 路径指向内盘 / 变量未设置）——测试未运行

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
# 更简单且跨平台的等价判据：挂载点必须是一个显式的卷挂载点——
#   macOS: /Volumes/<name>
#   Linux: /mnt/... 或 /media/...
# 本地约定要求产物放在外挂盘的 /Volumes/ 下，所以直接校验这一点。
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
    # 白名单：必须位于显式的卷挂载点下（macOS: /Volumes/<name>）。
    # 这比「排除 /System/Volumes/*」更稳——不依赖 macOS 具体把数据卷挂在哪，
    # 系统升级改了路径也不会静默失效（2026-10-28 首次实现用「挂载点==/」，
    # 在 macOS 上被判据漏掉，靠反向对照才发现）。
    case "$mount" in
        /Volumes/*) : ;;
        *) fail "拒绝运行：${label}=${path} 的挂载点是 ${mount}，不在 /Volumes/ 下。
            本机约定测试产物只能放在外挂卷（/Volumes/<name>）。" ;;
    esac
    echo "$mount"
}

MOUNT_POINT="$(check_external "$PYTEST_BASETEMP" PYTEST_BASETEMP)"
TMP_MOUNT="$(check_external "$TMPDIR" TMPDIR)"

# --- 6. Python 解释器：优先用环境变量，其次仓库内 venv，最后 PATH -------------
if [ -n "${PYTHON_BIN:-}" ]; then
    PY="$PYTHON_BIN"
elif [ -x ".venv/bin/python" ]; then
    PY=".venv/bin/python"
else
    PY="$(command -v python3 || command -v python)" || fail "找不到 python 解释器"
fi

echo "✅ 环境合规：TMPDIR=${TMPDIR}（挂载点 ${TMP_MOUNT}）"
echo "✅            basetemp=${PYTEST_BASETEMP}（挂载点 ${MOUNT_POINT}）"
echo "✅            python=${PY}"

# --- 7. 执行 ----------------------------------------------------------------
exec "$PY" -m pytest --basetemp="$PYTEST_BASETEMP" "$@"
