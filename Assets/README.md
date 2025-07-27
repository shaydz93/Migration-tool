# Assets Directory

This directory contains essential installer files and AI model components required for the Migration Tool to function properly.

## Required Files (to be added manually)

The following installer files must be manually downloaded and placed in this directory:

### Windows Installers
- **ChromeSetup.exe** - Windows offline Chrome installer
  - Alternative name: `Chrome-Windows.exe` (as referenced in main README)
- **python-installer.exe** - Python offline installer for Windows

### macOS Installers  
- **pmac.pkg** - Python offline installer for macOS
- **googlechrome.dmg** - Chrome offline installer for macOS
  - Alternative name: `Chrome-Mac.dmg` (as referenced in main README)

## AI Model Components

The `llama/` subdirectory should contain:
- **llama.exe** - Windows AI model executable
- **llama-mac** - macOS AI model executable  
- **model.gguf** - AI language model file

## Important Notes

- These files are **not included** in the repository due to licensing and size constraints
- Download installers from official sources only
- Ensure offline installers are compatible with target systems
- AI model files enable local report generation without internet connectivity

## File Sources

- **Chrome**: Download from [Google Chrome Enterprise](https://enterprise.google.com/chrome/chrome-browser/)
- **Python**: Download from [Python.org](https://www.python.org/downloads/)
- **AI Models**: Obtain compatible GGUF format models from appropriate sources

---

*This tool is designed to work completely offline once all required components are in place.*