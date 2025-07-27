#!/bin/bash

# migrate.sh - Universal Migration Tool (macOS)
# Runs on OLD computer to EXPORT data

cd "$(dirname "$0")"

echo "Running Migration Tool (Export)..."

PYTHON_PATH="/Library/Frameworks/Python.framework/Versions/3.11/bin/python3"

if [ ! -f "$PYTHON_PATH" ]; then
    echo "Python 3.11 not found. Installing from USB..."
    sudo installer -pkg "./Assets/pmac.pkg" -target /
    if [ ! -f "$PYTHON_PATH" ]; then
        echo "❌ Installation failed"
        exit 1
    fi
    echo "✅ Python installed!"
fi

echo "Starting migration GUI..."
"$PYTHON_PATH" ./migrate.py

read -p "Press Enter to exit..."