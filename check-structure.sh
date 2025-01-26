#!/bin/sh
echo "Checking project structure..."

# Check crypto-dbpoe
if [ ! -d "crypto-dbpoe" ]; then
    echo "ERROR: crypto-dbpoe directory not found"
    exit 1
fi

if [ ! -f "crypto-dbpoe/include/secp256k1.h" ]; then
    echo "ERROR: secp256k1.h not found in crypto-dbpoe/include"
    exit 1
fi

# Check u2sso module
if [ ! -d "common/common/u2sso" ]; then
    echo "ERROR: u2sso directory not found in common/common"
    exit 1
fi

if [ ! -f "common/common/u2sso/u2sso.pyx" ]; then
    echo "ERROR: u2sso.pyx not found"
    exit 1
fi

if [ ! -f "common/common/u2sso/__init__.py" ]; then
    echo "ERROR: __init__.py not found in u2sso"
    exit 1
fi

# Check setup file
if [ ! -f "setup_u2sso.py" ]; then
    echo "ERROR: setup_u2sso.py not found"
    exit 1
fi

echo "All required files found!"

# Show file contents for verification
echo "\nContents of setup_u2sso.py:"
cat setup_u2sso.py

echo "\nContents of common/common/u2sso/__init__.py:"
cat common/common/u2sso/__init__.py

echo "\nDirectory structure check complete."