#!/bin/bash

# start.sh - Universal Migration Tool (macOS)
# Runs on OLD computer to EXPORT data

cd "$(dirname "$0")"

echo "Running Migration Tool (Export)..."

# Path to python.org Python (includes tkinter)
PYTHON_PATH="/Library/Frameworks/Python.framework/Versions/3.11/bin/python3"

# If not found, install from USB
if [ ! -f "$PYTHON_PATH" ]; then
    echo "Python 3.11 not found. Installing from USB..."
    INSTALLER="./Assets/pmac.pkg"
    
    if [ ! -f "$INSTALLER" ]; then
        echo "❌ Installer not found at $INSTALLER"
        echo "Please ensure 'pmac.pkg' is in the Assets/ folder."
        open "./Assets"
        exit 1
    fi

    sudo installer -pkg "$INSTALLER" -target /
    
    if [ ! -f "$PYTHON_PATH" ]; then
        echo "❌ Installation failed"
        exit 1
    fi
    echo "✅ Python installed!"
fi

echo "Starting migration GUI..."
"$PYTHON_PATH" ./migrate.py

read -p "Press Enter to exit..."