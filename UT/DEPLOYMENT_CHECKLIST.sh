#!/bin/bash

# ╔════════════════════════════════════════════════════════════════╗
# ║     FIDO2-Node Unit Test Framework - Deployment Checklist     ║
# ║                      部署清单                                   ║
# ╚════════════════════════════════════════════════════════════════╝

set -e

PROJECT_ROOT="/Users/dqj/HDD/fido2Prjs/fido2-node"
UT_DIR="${PROJECT_ROOT}/UT"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  FIDO2-Node Unit Test Framework - Deployment Verification"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

check_count=0
pass_count=0
fail_count=0

# Function to check if file exists
check_file() {
    local file=$1
    local description=$2
    check_count=$((check_count + 1))
    
    if [ -f "$file" ]; then
        local size=$(du -h "$file" | cut -f1)
        echo -e "${GREEN}✓${NC} $check_count. $description ($size)"
        pass_count=$((pass_count + 1))
    else
        echo -e "${RED}✗${NC} $check_count. $description - NOT FOUND"
        fail_count=$((fail_count + 1))
    fi
}

# Function to check command exists
check_command() {
    local cmd=$1
    local description=$2
    check_count=$((check_count + 1))
    
    if command -v $cmd &> /dev/null; then
        echo -e "${GREEN}✓${NC} $check_count. $description"
        pass_count=$((pass_count + 1))
    else
        echo -e "${YELLOW}⚠${NC} $check_count. $description - NOT INSTALLED (optional)"
    fi
}

echo "1️⃣  检查单元测试文件 (Unit Test Files)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

check_file "${UT_DIR}/sql-injection.unit.test.js" "SQL 注入防护测试"
check_file "${UT_DIR}/functions.unit.test.js" "函数集成测试"
check_file "${UT_DIR}/run-unit-tests.sh" "单元测试执行脚本"
check_file "${UT_DIR}/package-test.json" "NPM 测试配置"

echo ""
echo "2️⃣  检查文档文件 (Documentation Files)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

check_file "${UT_DIR}/README.md" "完整测试框架指南 (760+ 行)"
check_file "${UT_DIR}/TEST_FRAMEWORK_SUMMARY.md" "框架总结文档 (400+ 行)"
check_file "${UT_DIR}/QUICK_REFERENCE.sh" "快速参考指南"

echo ""
echo "3️⃣  检查 SQL 注入修复文档"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

check_file "${PROJECT_ROOT}/../SQL_INJECTION_FIX_SUMMARY.md" "SQL 注入修复详情"
check_file "${PROJECT_ROOT}/../UNIT_TEST_COMPLETION_REPORT.md" "完成情况报告"

echo ""
echo "4️⃣  检查性能测试文件 (Performance Test Files - 保留)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

check_file "${UT_DIR}/register.performance.test.js" "注册性能测试"
check_file "${UT_DIR}/authenticate.performance.test.js" "认证性能测试"
check_file "${UT_DIR}/concurrency.performance.test.js" "并发压力测试"
check_file "${UT_DIR}/run-performance-tests.sh" "性能测试脚本"

echo ""
echo "5️⃣  检查支持文件 (Support Files)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

check_file "${UT_DIR}/mockDatabase.js" "Mock 数据库"
check_file "${UT_DIR}/mockData.js" "Mock 数据生成器"

echo ""
echo "6️⃣  检查构建环境 (Build Environment)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

check_command "node" "Node.js 已安装"
check_command "npm" "NPM 已安装"
check_command "bash" "Bash 已安装"

echo ""
echo "7️⃣  检查代码修复 (Code Fixes)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

check_count=$((check_count + 1))
if grep -q "function buildInClause" "${PROJECT_ROOT}/main.js"; then
    echo -e "${GREEN}✓${NC} $check_count. buildInClause() 辅助函数已添加"
    pass_count=$((pass_count + 1))
else
    echo -e "${RED}✗${NC} $check_count. buildInClause() 辅助函数 - NOT FOUND"
    fail_count=$((fail_count + 1))
fi

check_count=$((check_count + 1))
if grep -q "SqlString.format" "${PROJECT_ROOT}/main.js"; then
    echo -e "${GREEN}✓${NC} $check_count. SQL 参数化已应用"
    pass_count=$((pass_count + 1))
else
    echo -e "${RED}✗${NC} $check_count. SQL 参数化 - NOT FOUND"
    fail_count=$((fail_count + 1))
fi

echo ""
echo "8️⃣  检查测试清单内容 (Test Content Verification)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

check_count=$((check_count + 1))
sql_test_count=$(grep -c "describe\|it(" "${UT_DIR}/sql-injection.unit.test.js" 2>/dev/null || echo 0)
if [ "$sql_test_count" -gt 20 ]; then
    echo -e "${GREEN}✓${NC} $check_count. SQL 注入测试用例数: $sql_test_count"
    pass_count=$((pass_count + 1))
else
    echo -e "${RED}✗${NC} $check_count. SQL 注入测试用例不足"
    fail_count=$((fail_count + 1))
fi

check_count=$((check_count + 1))
func_test_count=$(grep -c "describe\|it(" "${UT_DIR}/functions.unit.test.js" 2>/dev/null || echo 0)
if [ "$func_test_count" -gt 10 ]; then
    echo -e "${GREEN}✓${NC} $check_count. 函数集成测试用例数: $func_test_count"
    pass_count=$((pass_count + 1))
else
    echo -e "${RED}✗${NC} $check_count. 函数集成测试用例不足"
    fail_count=$((fail_count + 1))
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  验证结果 (Verification Results)"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "总检查数: $check_count"
echo -e "通过: ${GREEN}$pass_count${NC}"
echo -e "失败: ${RED}$fail_count${NC}"
echo ""

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}✓ 所有检查通过！单元测试框架已准备就绪。${NC}"
    echo ""
    echo "📋 推荐的后续步骤："
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "1. 查看快速参考 (2 分钟):"
    echo "   bash ${UT_DIR}/QUICK_REFERENCE.sh"
    echo ""
    echo "2. 安装测试依赖 (1 分钟):"
    echo "   cd ${PROJECT_ROOT}"
    echo "   npm install --save-dev mocha nyc"
    echo ""
    echo "3. 运行单元测试 (30 秒):"
    echo "   bash ${UT_DIR}/run-unit-tests.sh all"
    echo ""
    echo "4. 查看完整文档:"
    echo "   cat ${UT_DIR}/README.md"
    echo ""
    echo "5. 运行性能测试 (可选，需要 1-2 分钟):"
    echo "   bash ${UT_DIR}/run-performance-tests.sh"
    echo ""
    exit 0
else
    echo -e "${RED}✗ 有些检查失败，请检查上面的错误信息。${NC}"
    exit 1
fi
