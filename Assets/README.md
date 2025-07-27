# Assets Directory

This directory contains offline installers and dependencies required for the Migration Tool to work in air-gapped environments.

## Required Files

Please manually add the following files to this directory:

### Windows Installers
- **ChromeSetup.exe** - Windows offline Chrome installer
- **python-installer.exe** - Python offline installer for Windows

### Mac Installers
- **pmac.pkg** - Python offline installer for Mac
- **googlechrome.dmg** - Chrome offline installer for Mac

## Notes

- These files must be obtained from their respective official sources
- The Migration Tool will look for these specific filenames
- All files should be placed directly in this Assets directory
- See the `llama/` subdirectory for AI model requirements
=======
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
main