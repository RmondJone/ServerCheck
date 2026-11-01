#!/usr/bin/env bash
# ==============================================================================
# Linux 服务器安全应急检测与后门排查 - 一键启动脚本
# ==============================================================================

set -e

# 定位脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}          Linux 服务器安全应急检测与后门排查系统 (一键启动)       ${NC}"
echo -e "${CYAN}================================================================${NC}"

# 1. 检测 Python 3
PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    # 检查 python 是否为 python3
    PY_VER=$(python -c 'import sys; print(sys.version_info[0])' 2>/dev/null || echo "2")
    if [ "$PY_VER" = "3" ]; then
        PYTHON_BIN="python"
    fi
fi

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[ERROR] 未检测到 Python 3 环境！${NC}"
    echo -e "请先安装 Python 3，例如："
    echo -e "  - Ubuntu / Debian : sudo apt-get update && sudo apt-get install -y python3"
    echo -e "  - CentOS / RHEL   : sudo yum install -y python3"
    exit 1
fi

# 2. 检查权限提示
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${YELLOW}[!] 当前以普通用户身份运行。${NC}"
    echo -e "${YELLOW}[!] 强烈建议使用: sudo ./run.sh 或 sudo python3 main.py 以获取完整的安全日志与系统敏感文件检测权限。${NC}\n"
fi

# 3. 执行检测主程序
exec "${PYTHON_BIN}" "${SCRIPT_DIR}/main.py" "$@"
