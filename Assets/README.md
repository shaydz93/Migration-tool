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