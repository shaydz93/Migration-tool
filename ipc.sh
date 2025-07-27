#!/bin/bash

# install_python_mac.sh
# Installs Python 3.11.9 on macOS if not present

set -e  # Stop on error

echo "Checking for Python 3..."

if command -v python3 &> /dev/null; then
    echo "Python 3 is already installed: $(python3 --version)"
    exit 0
fi

echo "Python 3 not found. Installing..."

# Create temp directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

# Download Python 3.11.9 macOS installer (Intel/Apple Silicon universal)
PYTHON_PKG="python-3.11.9-macos11.pkg"
PYTHON_URL="https://www.python.org/ftp/python/3.11.9/$PYTHON_PKG"

echo "Downloading $PYTHON_URL..."
curl -LO "$PYTHON_URL"

if [ ! -f "$PYTHON_PKG" ]; then
    echo "❌ Failed to download Python installer."
    exit 1
fi

echo "Installing Python 3.11.9..."
sudo installer -pkg "$PYTHON_PKG" -target /

# Clean up
rm -f "$PYTHON_PKG"
cd ~
rmdir "$TMP_DIR"

echo "✅ Python 3.11.9 installed successfully!"
echo "You can now run: python3 your_script.py"