#!/bin/bash

# Unit Tests Runner
# Separates unit tests from performance tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "======================================"
echo "FIDO2-Node Unit Tests"
echo "======================================"
echo ""

# Check if mocha is installed
if ! command -v mocha &> /dev/null; then
  echo "Installing mocha..."
  npm install --save-dev mocha
fi

# Parse command line arguments
TEST_TYPE="${1:-all}"
VERBOSE="${2:---reporter spec}"

case "$TEST_TYPE" in
  "sql-injection")
    echo "Running SQL Injection Unit Tests..."
    mocha "$SCRIPT_DIR/sql-injection.unit.test.js" "$VERBOSE" --timeout 5000
    ;;
  "functions")
    echo "Running Function Integration Tests..."
    mocha "$SCRIPT_DIR/functions.unit.test.js" "$VERBOSE" --timeout 5000
    ;;
  "all"|"unit")
    echo "Running All Unit Tests..."
    echo ""
    echo "1. SQL Injection Security Tests..."
    mocha "$SCRIPT_DIR/sql-injection.unit.test.js" "$VERBOSE" --timeout 5000
    echo ""
    echo "2. Function Integration Tests..."
    mocha "$SCRIPT_DIR/functions.unit.test.js" "$VERBOSE" --timeout 5000
    ;;
  *)
    echo "Usage: $0 [sql-injection|functions|all|unit]"
    exit 1
    ;;
esac

echo ""
echo "======================================"
echo "Unit Tests Completed Successfully!"
echo "======================================"
