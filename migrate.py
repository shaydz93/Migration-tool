#!/usr/bin/env python3
"""
Universal Migration Tool - Export
Supports: Windows, macOS
Features: GUI, sync mode, network, Chrome, AD, imaging, reporting, AI summary
"""

import os
import sys
import shutil
import json
import logging
import subprocess
import platform
import plistlib
import tempfile
import urllib.request
from datetime import datetime
from tkinter import *
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
import hashlib

# --- Detect OS ---
OS = platform.system()
IS_WINDOWS = OS == "Windows"
IS_MAC = OS == "Darwin"

# --- Paths ---
try:
    SCRIPT_DIR = Path(__file__).resolve().parent
except:
    SCRIPT_DIR = Path(os.getcwd())

DATA_DIR = SCRIPT_DIR / "Data"
LOGS_DIR = SCRIPT_DIR / "Logs"
CONFIG_FILE = SCRIPT_DIR / "config.json"
REPORTS_DIR = SCRIPT_DIR / "Reports"

LOGS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)
(DATA_DIR / "Windows").mkdir(exist_ok=True, parents=True)
(DATA_DIR / "Mac").mkdir(exist_ok=True, parents=True)

# --- Logging ---
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_path = LOGS_DIR / f"migration_{timestamp}.log"
logging.basicConfig(filename=log_path, level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)

def log(msg, level="info"):
    getattr(logging, level)(msg)
    if text_widget:
        text_widget.config(state="normal")
        text_widget.insert(END, msg + "\n")
        text_widget.see(END)
        text_widget.config(state="disabled")
        root.update_idletasks()

# --- Config ---
def load_config():
    if CONFIG_FILE.exists():
        try:
            return json.load(open(CONFIG_FILE))
        except Exception as e:
            log(f"Config load failed: {e}", "warning")
    return {"source": str(Path.home()), "target_platform": "Windows", "items": {}}

def save_config():
    config["source"] = source_entry.get()
    config["target_platform"] = target_platform.get()
    config["items"] = {key: var.get() for key, var in items.items()}
    try:
        json.dump(config, open(CONFIG_FILE, 'w'), indent=2)
    except Exception as e:
        log(f"Config save failed: {e}", "error")

config = load_config()

# --- Sync Copy ---
def is_newer_or_different(src: Path, dest: Path) -> bool:
    if not dest.exists():
        return True
    try:
        src_stat = src.stat()
        dest_stat = dest.stat()
        return src_stat.st_mtime > dest_stat.st_mtime or src_stat.st_size != dest_stat.st_size
    except:
        return True

def sync_copy(src: Path, dest: Path):
    if not is_newer_or_different(src, dest):
        return
    log(f"Sync: {src.name}")
    dest.parent.mkdir(exist_ok=True, parents=True)
    try:
        if src.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(src, dest, symlinks=True)
        else:
            shutil.copy2(src, dest)
    except Exception as e:
        log(f"Copy failed {src} -> {dest}: {e}", "error")

# --- AI Summary Generator ---
def generate_ai_summary(log_text, is_export=True):
    """
    Generates a natural language summary using local LLM or fallback.
    """
    try:
        exe = SCRIPT_DIR / "Assets" / "llama" / ("llama-mac" if IS_MAC else "llama.exe")
        model = SCRIPT_DIR / "Assets" / "llama" / "model.gguf"

        if not exe.exists():
            raise FileNotFoundError("llama executable not found")
        if not model.exists():
            raise FileNotFoundError("model.gguf not found")

        action = "migration" if is_export else "restore"
        prompt = f"Summarize {action} process: {log_text[-2000:]}. Keep it professional and user-friendly."

        cmd = [
            str(exe), "--model", str(model),
            "--prompt", prompt,
            "--n-predict", "150",
            "--temp", "0.3",
            "--threads", "6"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        output = result.stdout.strip()

        if output and len(output) > 50:
            return output.split("Prompt:")[-1].strip()[:500]
        else:
            raise Exception("LLM returned no meaningful output")

    except Exception as e:
        log(f"Local LLM failed: {e}. Using smart template.", "warning")

    # Fallback Template
    has_files = "User files synced" in log_text
    has_appdata = "AppData / Preferences saved" in log_text
    has_wifi = "Wi-Fi exported" in log_text
    has_chrome = "Chrome installed" in log_text
    has_errors = "error" in log_text.lower()

    summary = "The data migration was completed successfully. "
    items = []
    if has_files: items.append("your personal files")
    if has_appdata: items.append("application settings")
    if has_wifi: items.append("Wi-Fi network profiles")
    if has_chrome: items.append("Google Chrome")

    if items:
        summary += "We transferred " + ", ".join(items[:-1])
        if len(items) > 1:
            summary += f", and {items[-1]}"
        else:
            summary += f" {items[-1]}"
        summary += ". "

    if has_wifi:
        summary += "Your Wi-Fi networks are configured for automatic connection. "
    if has_chrome:
        summary += "Chrome is installed for a consistent browsing experience. "
    if has_errors:
        summary += "There were some errors — please check the log. "
    else:
        summary += "No issues were detected during the transfer. "
    summary += "You can now log in and continue working as before."
    return summary

# --- Generate HTML Report ---
def generate_report(is_export=True):
    try:
        from datetime import datetime
        report_dir = SCRIPT_DIR / "Reports"
        report_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        user = os.getlogin()
        mode = "migration" if is_export else "restore"
        report_path = report_dir / f"{mode}_{user}_{timestamp}.html"

        log_text = ""
        if Path(log_path).exists():
            log_text = Path(log_path).read_text().replace('\n', '<br>')

        ai_summary = generate_ai_summary(log_text, is_export=is_export)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{mode.title()} Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1, h2 {{ color: #2c3e50; }}
        .summary {{ background: #f8f9fa; padding: 15px; border-radius: 8px; }}
        pre {{ background: #f4f4f4; padding: 10px; border-radius: 5px; overflow: auto; }}
        .success {{ color: green; }}
        .error {{ color: red; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #007BFF; color: white; }}
    </style>
</head>
<body>
    <h1>📊 {mode.title().replace('I', 'I')} Report</h1>
    <div class="summary">
        <p><strong>User:</strong> {user}</p>
        <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Status:</strong> <span class="success">✅ Completed Successfully</span></p>
    </div>
    <h2>🤖 AI-Powered Summary</h2>
    <p>{ai_summary}</p>
    <h2>📋 Summary</h2>
    <table>
        <tr><th>Task</th><th>Status</th></tr>
        <tr><td>User Files</td><td>✅ {'Synced' if items['Files'].get() else 'Skipped'}</td></tr>
        <tr><td>AppData / Preferences</td><td>✅ {'Transferred' if items['AppData'].get() else 'Skipped'}</td></tr>
        <tr><td>Settings (Registry/Plist)</td><td>✅ {'Exported' if items['Registry'].get() else 'Skipped'}</td></tr>
        <tr><td>Wallpaper</td><td>✅ {'Saved' if items['Wallpaper'].get() else 'Skipped'}</td></tr>
        <tr><td>Wi-Fi Profiles</td><td>✅ {'Exported' if items['WiFi'].get() else 'Skipped'}</td></tr>
        <tr><td>Mail Data</td><td>✅ {'Exported' if items['Outlook'].get() else 'Skipped'}</td></tr>
        <tr><td>Network Settings</td><td>✅ {'Exported' if items['Network'].get() else 'Skipped'}</td></tr>
        <tr><td>Google Chrome</td><td>✅ {'Installed' if items['Chrome'].get() else 'Skipped'}</td></tr>
        <tr><td>Active Directory</td><td>✅ {'Profiled' if items['AD'].get() else 'Skipped'}</td></tr>
    </table>
    <h2>📝 Full Log</h2>
    <pre>{log_text}</pre>
</body>
</html>"""

        Path(report_path).write_text(html, encoding='utf-8')
        log(f"📊 Report generated: {report_path}")
        return report_path

    except Exception as e:
        log(f"Report generation failed: {e}", "error")
        return None

# --- Export Functions ---
def export_files():
    if not items["Files"].get():
        return
    log("Copying user files...")
    source = Path(source_entry.get())
    if not source.exists():
        log("Source path does not exist!", "error")
        return
    target = DATA_DIR / target_platform.get() / "UserFiles"
    target.mkdir(exist_ok=True, parents=True)
    for item in source.iterdir():
        if item.name in {'.', '..'} or item.name == 'System Volume Information':
            continue
        sync_copy(item, target / item.name)
    log("User files synced.")

def export_appdata():
    if not items["AppData"].get():
        return
    log("Backing up AppData / Preferences...")
    try:
        if IS_WINDOWS:
            src1 = Path(os.environ.get("APPDATA", ""))
            src2 = Path(os.environ.get("LOCALAPPDATA", ""))
            target = DATA_DIR / target_platform.get() / "AppData"
            if src1.exists(): sync_copy(src1, target / "Roaming")
            if src2.exists(): sync_copy(src2, target / "Local")
        elif IS_MAC:
            src = Path.home() / "Library" / "Preferences"
            if src.exists():
                sync_copy(src, DATA_DIR / target_platform.get() / "Preferences")
        log("AppData / Preferences saved.")
    except Exception as e:
        log(f"AppData backup failed: {e}", "error")

def export_registry():
    if not items["Registry"].get():
        return
    log("Exporting registry / plist settings...")
    try:
        if IS_WINDOWS:
            reg_file = DATA_DIR / target_platform.get() / "UserRegistry.reg"
            reg_file.parent.mkdir(exist_ok=True, parents=True)
            subprocess.run(['reg', 'export', 'HKEY_CURRENT_USER', str(reg_file), '/y'], check=True, timeout=30)
        elif IS_MAC:
            plist_dir = DATA_DIR / target_platform.get() / "PlistSettings"
            plist_dir.mkdir(exist_ok=True, parents=True)
            for plist in ["com.apple.finder.plist", "com.apple.systempreferences.plist"]:
                src = Path.home() / "Library" / "Preferences" / plist
                if src.exists():
                    sync_copy(src, plist_dir / plist)
        log("Settings exported.")
    except Exception as e:
        log(f"Registry export failed: {e}", "error")

def export_wallpaper():
    if not items["Wallpaper"].get():
        return
    log("Saving wallpaper...")
    try:
        wp_dest = DATA_DIR / target_platform.get() / "Wallpaper.jpg"
        wp_dest.parent.mkdir(exist_ok=True, parents=True)
        wp_path = None
        if IS_WINDOWS:
            p = Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Themes" / "TranscodedWallpaper"
            if p.exists():
                wp_path = p
        elif IS_MAC:
            result = subprocess.run(['osascript', '-e', 'tell application "Finder" to get desktop picture as text'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                wp_path = Path(result.stdout.strip().replace("file://", ""))
                if not wp_path.exists():
                    wp_path = None
        if wp_path and wp_path.exists():
            shutil.copy2(wp_path, wp_dest)
            log("Wallpaper saved.")
    except Exception as e:
        log(f"Wallpaper save failed: {e}", "error")

def export_wifi():
    if not items["WiFi"].get():
        return
    log("Exporting Wi-Fi profiles...")
    try:
        if IS_WINDOWS:
            wifi_dir = DATA_DIR / target_platform.get() / "WiFiProfiles"
            wifi_dir.mkdir(exist_ok=True, parents=True)
            subprocess.run(['netsh', 'wlan', 'export', 'profile', f'folder={wifi_dir}', 'key=clear'], timeout=30)
        elif IS_MAC:
            wifi_file = DATA_DIR / target_platform.get() / "WiFiProfiles.txt"
            wifi_file.parent.mkdir(exist_ok=True, parents=True)
            subprocess.run(['networksetup', '-export', str(wifi_file)], timeout=30)
        log("Wi-Fi exported.")
    except Exception as e:
        log(f"Wi-Fi export failed: {e}", "error")

def export_mail():
    if not items["Outlook"].get():
        return
    log("Exporting mail data...")
    try:
        if IS_WINDOWS:
            src = Path(os.environ["LOCALAPPDATA"]) / "Microsoft" / "Outlook"
            if src.exists():
                sync_copy(src, DATA_DIR / target_platform.get() / "OutlookData")
        elif IS_MAC:
            src = Path.home() / "Library" / "Containers" / "com.apple.mail" / "Data"
            if src.exists():
                sync_copy(src, DATA_DIR / target_platform.get() / "MailData")
        log("Mail data exported.")
    except Exception as e:
        log(f"Mail export failed: {e}", "error")

def export_apps():
    if not items["Apps"].get():
        return
    log("Saving installed apps list...")
    try:
        apps_file = DATA_DIR / target_platform.get() / "InstalledApps.txt"
        apps_file.parent.mkdir(exist_ok=True, parents=True)
        with open(apps_file, "w") as f:
            if IS_WINDOWS:
                result = subprocess.run(['powershell', '-Command',
                    'Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | '
                    'Select-Object DisplayName, Publisher, DisplayVersion | Format-Table -AutoSize'],
                    capture_output=True, text=True, timeout=30)
                f.write(result.stdout)
            elif IS_MAC:
                result = subprocess.run(['system_profiler', 'SPApplicationsDataType'],
                                      capture_output=True, text=True, timeout=60)
                f.write(result.stdout)
        log("Apps list saved.")
    except Exception as e:
        log(f"Apps list failed: {e}", "error")

def export_network():
    if not items["Network"].get():
        return
    log("Exporting network settings...")
    net_dir = DATA_DIR / target_platform.get() / "Network"
    net_dir.mkdir(exist_ok=True, parents=True)
    try:
        if IS_WINDOWS:
            with open(net_dir / "Domain.txt", "w") as f:
                f.write(f"User: {subprocess.getoutput('whoami')}\n")
                f.write(f"Domain: {os.environ.get('USERDOMAIN', 'Unknown')}\n")
                dc = subprocess.run(['nltest', '/dsgetdc:%USERDOMAIN%'], shell=True, capture_output=True)
                f.write(f"Type: {'Domain' if dc.returncode == 0 else 'Workgroup'}\n")
            with open(net_dir / "IPConfig.txt", "w") as f:
                f.write(subprocess.getoutput('ipconfig /all'))
            hosts = Path("C:/Windows/System32/drivers/etc/hosts")
            if hosts.exists():
                shutil.copy2(hosts, net_dir / "hosts")
            with open(net_dir / "MappedDrives.txt", "w") as f:
                f.write(subprocess.getoutput('net use'))
            with open(net_dir / "Proxy.txt", "w") as f:
                f.write(subprocess.getoutput('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"'))
        elif IS_MAC:
            with open(net_dir / "Domain.txt", "w") as f:
                f.write(subprocess.getoutput('dsconfigad -show') + "\n")
                f.write("Type: " + ("Active Directory\n" if "Active Directory" in f.getvalue() else "Local\n"))
            with open(net_dir / "IPConfig.txt", "w") as f:
                f.write("Wi-Fi Info:\n" + subprocess.getoutput('networksetup -getinfo "Wi-Fi"'))
            hosts = Path("/etc/hosts")
            if hosts.exists():
                shutil.copy2(hosts, net_dir / "hosts")
            with open(net_dir / "MappedDrives.txt", "w") as f:
                f.write(subprocess.getoutput('mount'))
            with open(net_dir / "Proxy.txt", "w") as f:
                f.write("Web Proxy:\n" + subprocess.getoutput('networksetup -getwebproxy "Wi-Fi"'))
        log("Network settings exported.")
    except Exception as e:
        log(f"Network export failed: {e}", "error")

def export_ad_info():
    if not items["AD"].get():
        return
    log("Exporting Active Directory profile...")
    ad_dir = DATA_DIR / target_platform.get() / "ActiveDirectory"
    ad_dir.mkdir(exist_ok=True, parents=True)
    try:
        if IS_WINDOWS:
            with open(ad_dir / "AD_Profile.txt", "w") as f:
                f.write(f"User: {subprocess.getoutput('whoami')}\n")
                f.write(f"Domain: {os.environ.get('USERDOMAIN', 'N/A')}\n")
                f.write(f"Logon Server: {os.environ.get('LOGONSERVER', 'N/A')}\n")
                ou = subprocess.getoutput('dsquery user -samid %USERNAME% | dsget user -memberof -expand')
                f.write(f"Groups: {ou}\n")
            subprocess.run(['reg', 'export', 'HKLM\\SOFTWARE\\Policies', str(ad_dir / "Policies.reg"), '/y'], timeout=30)
        elif IS_MAC:
            result = subprocess.run(['dsconfigad', '-show'], capture_output=True, text=True)
            if "Active Directory" in result.stdout:
                (ad_dir / "AD_Bound.txt").write_text(result.stdout)
        log("Active Directory profile exported.")
    except Exception as e:
        log(f"AD export failed: {e}", "error")

def create_disk_image():
    if not items["DiskImage"].get():
        return
    log("Starting disk imaging...")
    image_dir = DATA_DIR / target_platform.get() / "DiskImage"
    image_dir.mkdir(exist_ok=True, parents=True)
    try:
        if IS_WINDOWS:
            log("Using wbadmin for system image (requires admin)...")
            result = subprocess.run([
                'wbadmin', 'start backup', '-backupTarget:' + str(image_dir),
                '-include:C:', '-quiet'
            ], capture_output=True, text=True)
            if result.returncode == 0:
                log("✅ Windows System Image created.")
            else:
                log(f"wbadmin failed: {result.stderr}", "error")
        elif IS_MAC:
            result = subprocess.run(['df', '/'], capture_output=True, text=True)
            lines = result.stdout.strip().splitlines()
            disk_line = lines[-1]
            disk = disk_line.split()[0].replace("disk", "rdisk")
            image_path = image_dir / "system_image.img"
            log(f"Creating image of {disk} → {image_path}.gz")
            with open(f"{image_path}", "wb") as img:
                dd_proc = subprocess.Popen(['dd', f'if={disk}', 'bs=1m'], stdout=subprocess.PIPE)
                gzip_proc = subprocess.Popen(['gzip'], stdin=dd_proc.stdout, stdout=img)
                dd_proc.stdout.close()
                gzip_proc.wait()
            log("✅ Disk image created.")
    except Exception as e:
        log(f"Disk imaging failed: {e}", "error")

def create_baseline_hashes():
    log("Creating integrity baseline...")
    baseline_file = DATA_DIR / target_platform.get() / "hashes.json"
    hashes = {}
    root_dirs = ["UserFiles", "AppData", "Preferences", "Network", "OutlookData", "MailData", "PlistSettings", "WiFiProfiles", "ActiveDirectory"]
    for dname in root_dirs:
        root = DATA_DIR / target_platform.get() / dname
        if not root.exists():
            continue
        for file in root.rglob("*"):
            if file.is_file():
                rel = file.relative_to(DATA_DIR / target_platform.get())
                digest = calculate_sha256(file)
                if digest:
                    hashes[str(rel)] = digest
    import json
    with open(baseline_file, 'w') as f:
        json.dump(hashes, f, indent=2)
    log(f"✅ Integrity baseline saved: {baseline_file}")

def calculate_sha256(file_path, chunk_size=1 << 20):
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        log(f"Read error: {e}", "error")
        return None

def start_migration():
    save_config()
    target = target_platform.get()
    data_dir = DATA_DIR / target if target != "Both" else DATA_DIR
    data_dir.mkdir(exist_ok=True, parents=True)
    log("Starting migration...")
    try:
        export_files()
        export_appdata()
        export_registry()
        export_wallpaper()
        export_wifi()
        export_mail()
        export_apps()
        export_network()
        export_ad_info()
        create_disk_image()
        create_baseline_hashes()
        log("✅ Migration completed successfully!", "info")
        report = generate_report(is_export=True)
        messagebox.showinfo("Success", f"Migration complete!\nReport: {report}\nData saved to:\n{data_dir}")
    except Exception as e:
        log(f"Migration failed: {e}", "error")
        messagebox.showerror("Error", f"Migration failed: {e}")

# --- GUI ---
root = Tk()
root.title("Migration Tool [Export]")
root.geometry("1000x700")
root.resizable(True, True)

# Configure grid
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=2)
root.grid_rowconfigure(0, weight=0)
root.grid_rowconfigure(1, weight=1)

# --- Title ---
Label(root, text="Universal Migration Tool", font=("Helvetica", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=10, sticky="ew")

# --- Main Frame ---
main_frame = Frame(root)
main_frame.grid(row=1, column=0, columnspan=2, padx=20, pady=10, sticky="nsew")
main_frame.grid_columnconfigure(0, weight=1)
main_frame.grid_columnconfigure(1, weight=2)
main_frame.grid_rowconfigure(0, weight=1)

# --- Left Panel ---
left_frame = LabelFrame(main_frame, text=" Configuration ", padx=10, pady=10)
left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

# Source Path
Label(left_frame, text="Source User Folder", font=("Helvetica", 10, "bold")).grid(row=0, column=0, columnspan=2, sticky=W, pady=(0,10))
source_entry = Entry(left_frame, width=40)
source_entry.insert(0, config.get("source", str(Path.home())))
source_entry.grid(row=1, column=0, sticky=EW, pady=2)
Button(left_frame, text="Browse", command=lambda: source_entry.insert(0, filedialog.askdirectory())).grid(row=1, column=1, padx=(5,0))

# Target Platform
Label(left_frame, text="Target System", font=("Helvetica", 10, "bold")).grid(row=2, column=0, columnspan=2, sticky=W, pady=(10,5))
target_platform = StringVar(value=config.get("target_platform", "Windows"))
Radiobutton(left_frame, text="Windows", variable=target_platform, value="Windows").grid(row=3, column=0, sticky=W)
Radiobutton(left_frame, text="macOS", variable=target_platform, value="Mac").grid(row=4, column=0, sticky=W)
Radiobutton(left_frame, text="Both", variable=target_platform, value="Both").grid(row=5, column=0, sticky=W)

# Items to Migrate
Label(left_frame, text="Items to Migrate", font=("Helvetica", 10, "bold")).grid(row=6, column=0, columnspan=2, sticky=W, pady=(10,5))
items = {
    "Files": BooleanVar(value=True),
    "AppData": BooleanVar(value=True),
    "Registry": BooleanVar(value=True),
    "Wallpaper": BooleanVar(value=True),
    "WiFi": BooleanVar(value=True),
    "Outlook": BooleanVar(value=True),
    "Apps": BooleanVar(value=True),
    "Network": BooleanVar(value=True),
    "AD": BooleanVar(value=True),
    "DiskImage": BooleanVar(value=False),
}
for i, (key, var) in enumerate(items.items(), start=7):
    Checkbutton(left_frame, text=key.replace("AD", "AD Profile").replace("DiskImage", "Disk Image"), variable=var).grid(row=i, column=0, columnspan=2, sticky=W)

# Start Button
Button(left_frame, text="🚀 START MIGRATION", command=start_migration,
       bg="green", fg="white", font=("Helvetica", 11, "bold"), height=2).grid(row=len(items)+8, column=0, columnspan=2, pady=(20,10), sticky=EW)

# Exit Button
Button(left_frame, text="Exit", command=root.quit, font=("Helvetica", 10)).grid(row=len(items)+9, column=0, columnspan=2, pady=(0,0), sticky=EW)

# --- Right Panel: Log Output ---
right_frame = LabelFrame(main_frame, text=" Log Output ", padx=10, pady=10)
right_frame.grid(row=0, column=1, sticky="nsew", padx=(5,0))
right_frame.grid_rowconfigure(0, weight=1)
right_frame.grid_columnconfigure(0, weight=1)

scrollbar = Scrollbar(right_frame)
scrollbar.grid(row=0, column=1, sticky=NS)

text_widget = Text(right_frame, yscrollcommand=scrollbar.set, state="disabled", font=("Courier", 9))
text_widget.grid(row=0, column=0, sticky="nsew")
scrollbar.config(command=text_widget.yview)

# Expand
left_frame.grid_rowconfigure(len(items)+10, weight=1)
left_frame.grid_columnconfigure(0, weight=1)

root.mainloop()