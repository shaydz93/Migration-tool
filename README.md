
# 🚀 Universal Migration Toolkit

A fully offline, cross-platform tool for migrating user data from old computers to new ones — with AI-powered reporting and enterprise features.

---

## ✅ Supported Platforms

- **macOS** (10.15+)
- **Windows** (10/11)

> **Note:** Linux is not supported.

---

## 📦 What It Does

- 📁 Migrate user files, settings, and apps  
- 🔐 Preserve Wi-Fi, Chrome, Active Directory, and network settings  
- 🖼️ Retain wallpaper and preferences  
- 💾 Create bootable disk images (optional)  
- 🧠 Generate **AI-powered migration reports**  
- 🔍 Verify data integrity before restore  

> All without internet — runs from a USB drive.

---

## 🛠️ How It Works

### 1. On the Old Computer (Export Data)

```bash
./start.sh        # macOS  
start.bat         # Windows
```

- Select user folder  
- Choose what to migrate  
- Click **"Start Migration"**  
- Data saved to `/Data/`

### 2. On the New Computer (Restore Data)

```bash
./restore.sh      # macOS  
restore.bat       # Windows
```

- Auto-detects migration data  
- Restores files, settings, Chrome, and more  
- Joins Active Directory (if selected)  
- Generates a professional HTML report  

---

## 🧩 Key Features

| Feature                            | Supported |
|------------------------------------|-----------|
| User Files & Folders               | ✅         |
| AppData / Preferences              | ✅         |
| Registry / Plist Settings          | ✅         |
| Wallpaper Retention                | ✅         |
| Wi-Fi Profiles                     | ✅         |
| Mail Data (Outlook, Mail.app)      | ✅         |
| Installed Apps List                | ✅         |
| Network Settings (Hosts, Drives)   | ✅         |
| Active Directory Join              | ✅         |
| Google Chrome Installation         | ✅         |
| Disk Imaging (Bootable Backup)     | ✅         |
| Integrity Verification (SHA-256)   | ✅         |
| AI-Powered Report Summary          | ✅         |
| Works Offline                      | ✅         |
| No Admin Rights Required (Export)  | ✅         |
| Silent Install (Python, Chrome)    | ✅         |

---

## 📁 Folder Structure

```
MigrationTool/
├── start.sh              # Launch export on macOS
├── start.bat             # Launch export on Windows
├── restore.sh            # Launch restore on macOS
├── restore.bat           # Launch restore on Windows
├── migrate.py            # Export tool (GUI)
├── restore.py            # Import tool (GUI)
├── Assets/
│   ├── pmac.pkg
│   ├── python-installer.exe
│   ├── Chrome-Windows.exe
│   ├── Chrome-Mac.dmg
│   └── llama/
│       ├── llama.exe
│       ├── llama-mac
│       └── model.gguf
├── Data/                 # Exported user data
├── Logs/                 # Migration logs
├── Reports/              # AI-generated HTML summaries
└── README.md             # This guide
```

---

## 🚀 Getting Started

1. **Copy** the `MigrationTool` folder to a USB drive  
2. On the **old computer**, run:
    ```bash
    start.sh    (macOS)  
    start.bat   (Windows)
    ```
3. Follow the GUI to **export data**  
4. Move USB to **new computer**  
5. Run:
    ```bash
    restore.sh    (macOS)  
    restore.bat   (Windows)
    ```
6. Click **"Start Restore"** and wait

> ✅ A report will be saved to `/Reports/`

---

## 🤖 AI-Powered Reporting

After each migration, a **natural language summary** is generated using a **local LLM** (no internet required).

> *"The migration was completed successfully. All user files, application settings, and Wi-Fi profiles were transferred. Google Chrome was installed, and the system is ready for use. No errors were detected."*

Reports are saved as **HTML files**.

---

## 🔐 Security & Trust

- All data stays on the USB — **no cloud, no internet**
- SHA-256 integrity checks ensure no corruption
- Optional **code signing** for enterprise deployments

---

## 📄 License

This tool is for internal use only. Assets (like Chrome installers) are subject to their respective licenses.

---

_Developed with ❤️ for seamless, offline, enterprise-ready migrations._
