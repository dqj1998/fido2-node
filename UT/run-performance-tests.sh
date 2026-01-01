#!/bin/bash

# FIDO2-Node Performance Testing - Quick Start Guide
# This script demonstrates how to run the complete performance test suite

echo "======================================"
echo "FIDO2-Node Performance Testing Suite"
echo "======================================"
echo ""

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    echo "Error: package.json not found. Please run this script from fido2-node root directory."
    exit 1
fi

echo "1. Installing dependencies..."
npm install
echo "✓ Dependencies installed"
echo ""

echo "2. Running Registration Performance Tests..."
npm run test:register
echo ""

echo "3. Running Authentication Performance Tests..."
npm run test:authenticate
echo ""

echo "4. Running Concurrency and Stress Tests..."
npm run test:concurrency
echo ""

echo "5. Generating Performance Reports..."
npm run test:report
echo ""

echo "======================================"
echo "Test Summary"
echo "======================================"
echo ""

# Check if results exist
if [ -d "UT/results" ]; then
    echo "Results saved in: UT/results/"
    echo ""
    echo "Files generated:"
    ls -lh UT/results/*.json 2>/dev/null | awk '{print "  - " $NF}'
    echo ""
    echo "Reports generated:"
    ls -lh UT/results/reports/ 2>/dev/null | grep -E "\.(json|md)$" | awk '{print "  - " $NF}'
    echo ""
    echo "Next steps:"
    echo "  1. Open UT/results/reports/*.md to view the Markdown report"
    echo "  2. Review UT/results/reports/*.json for detailed metrics"
    echo "  3. Compare P95 percentiles with your performance targets"
    echo ""
fi

echo "======================================"
echo "Performance Testing Complete!"
echo "======================================"
