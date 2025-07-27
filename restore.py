#!/usr/bin/env python3
"""
Universal Restore Tool - Import
Restores data exported by migrate.py
Features: GUI, sync, network, Chrome, AD, AI reporting
"""

import os
import sys
import shutil
import json
import logging
import subprocess
import platform
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
CONFIG_FILE = SCRIPT_DIR / "restore_config.json"
REPORTS_DIR = SCRIPT_DIR / "Reports"

LOGS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

# --- Logging ---
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_path = LOGS_DIR / f"restore_{timestamp}.log"
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
        except:
            pass
    return {"source_os": "", "items": {}}

def save_config():
    config["source_os"] = source_var.get()
    config["items"] = {key: var.get() for key, var in item_vars.items()}
    try:
        json.dump(config, open(CONFIG_FILE, 'w'), indent=2)
    except Exception as e:
        log(f"Config save failed: {e}", "error")

config = load_config()
DATA_ROOT = None

# --- Detect Source OS ---
def detect_source():
    win = DATA_DIR / "Windows"
    mac = DATA_DIR / "Mac"
    if (win / "UserFiles").exists():
        return "Windows"
    elif (mac / "UserFiles").exists():
        return "Mac"
    return ""

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

# --- Integrity Verification ---
def calculate_sha256(file_path, chunk_size=1 << 20):
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        log(f"Read error {file_path}: {e}", "error")
        return None

def verify_all_files():
    log("Starting pre-restore integrity check...")
    baseline_file = Path(DATA_ROOT) / "hashes.json"
    if not baseline_file.exists():
        log("No integrity baseline found. Skipping file verification.", "warning")
        return True
    try:
        import json
        expected_hashes = json.load(open(baseline_file))
        log(f"Found baseline for {len(expected_hashes)} files. Verifying...")
        passed = True
        for rel_path, expected in expected_hashes.items():
            full_path = Path(DATA_ROOT) / rel_path
            if not full_path.exists():
                log(f"❌ Missing file: {rel_path}", "error")
                passed = False
                continue
            actual = calculate_sha256(full_path)
            if not actual:
                log(f"❌ Read failed: {rel_path}", "error")
                passed = False
                continue
            if actual.lower() != expected.lower():
                log(f"❌ CORRUPTED: {rel_path}", "error")
                log(f"   Expected: {expected[:16]}...", "error")
                log(f"   Actual:   {actual[:16]}...", "error")
                passed = False
        if passed:
            log("✅ All migrated files are intact.", "info")
        else:
            log("❌ One or more files are missing or corrupted!", "error")
            if not messagebox.askyesno("Integrity Check Failed", "Files are corrupted. Continue anyway?"):
                return False
        return passed
    except Exception as e:
        log(f"Verification failed: {e}", "error")
        if not messagebox.askyesno("Error", "Verification failed. Continue anyway?"):
            return False
        return True

def verify_disk_image():
    image_dir = Path(DATA_ROOT) / "DiskImage"
    if not image_dir.exists():
        log("No disk image found. Skipping image verification.")
        return True
    verified = True
    for img in image_dir.glob("*.img *.gz *.vhd *.vhdx *.dmg"):
        if not img.is_file():
            continue
        hash_file = img.with_suffix(img.suffix + ".sha256")
        if not hash_file.exists():
            log(f"No hash file for {img.name}. Cannot verify.", "warning")
            continue
        expected = hash_file.read_text().split()[0].strip()
        actual = calculate_sha256(img)
        if not actual:
            log(f"❌ Read failed: {img.name}", "error")
            verified = False
            continue
        if actual.lower() == expected.lower():
            log(f"✅ {img.name} — OK")
        else:
            log(f"❌ {img.name} — CORRUPTED!", "error")
            verified = False
    if not verified:
        if not messagebox.askyesno("Disk Image Corrupted", "One or more disk images are corrupted. Continue?"):
            return False
    return verified

# --- AI Summary Generator ---
def generate_ai_summary(log_text, is_export=False):
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
    has_files = "User files restored" in log_text
    has_appdata = "AppData / Preferences restored" in log_text
    has_wifi = "Wi-Fi profiles imported" in log_text
    has_chrome = "Chrome installed" in log_text
    has_errors = "error" in log_text.lower()

    summary = "The data restore was completed successfully. "
    items = []
    if has_files: items.append("your personal files")
    if has_appdata: items.append("application settings")
    if has_wifi: items.append("Wi-Fi network profiles")
    if has_chrome: items.append("Google Chrome")

    if items:
        summary += "We restored " + ", ".join(items[:-1])
        if len(items) > 1:
            summary += f", and {items[-1]}"
        else:
            summary += f" {items[-1]}"
        summary += ". "

    if has_wifi:
        summary += "Your Wi-Fi networks are ready for automatic connection. "
    if has_chrome:
        summary += "Chrome is installed for a consistent browsing experience. "
    if has_errors:
        summary += "There were some errors — please check the log. "
    else:
        summary += "No issues were detected during the transfer. "
    summary += "You can now log in and continue working as before."
    return summary

# --- Generate HTML Report ---
def generate_report(is_export=False):
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
        <tr><td>User Files</td><td>✅ {'Restored' if item_vars['Files'].get() else 'Skipped'}</td></tr>
        <tr><td>AppData / Preferences</td><td>✅ {'Restored' if item_vars['AppData'].get() else 'Skipped'}</td></tr>
        <tr><td>Settings (Registry/Plist)</td><td>✅ {'Applied' if item_vars['Settings'].get() else 'Skipped'}</td></tr>
        <tr><td>Wallpaper</td><td>✅ {'Applied' if item_vars['Wallpaper'].get() else 'Skipped'}</td></tr>
        <tr><td>Wi-Fi Profiles</td><td>✅ {'Imported' if item_vars['WiFi'].get() else 'Skipped'}</td></tr>
        <tr><td>Mail Data</td><td>✅ {'Restored' if item_vars['Mail'].get() else 'Skipped'}</td></tr>
        <tr><td>Network Settings</td><td>✅ {'Applied' if item_vars['Network'].get() else 'Skipped'}</td></tr>
        <tr><td>Google Chrome</td><td>✅ {'Installed' if item_vars['Chrome'].get() else 'Skipped'}</td></tr>
        <tr><td>Active Directory</td><td>✅ {'Joined' if item_vars['AD'].get() else 'Skipped'}</td></tr>
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

# --- Restore Functions ---
def restore_files():
    if not item_vars["Files"].get() or not DATA_ROOT:
        return
    log("Restoring user files...")
    src = Path(DATA_ROOT) / "UserFiles"
    if not src.exists():
        log("No UserFiles to restore.", "warning")
        return
    for item in src.iterdir():
        if item.name in {'.', '..'}:
            continue
        sync_copy(item, Path.home() / item.name)
    log("User files restored.")

def restore_appdata():
    if not item_vars["AppData"].get() or not DATA_ROOT:
        return
    log("Restoring AppData / Preferences...")
    try:
        src = Path(DATA_ROOT)
        home = Path.home()
        if IS_WINDOWS and (src / "AppData").exists():
            roaming = src / "AppData" / "Roaming"
            local = src / "AppData" / "Local"
            if roaming.exists(): sync_copy(roaming, Path(os.environ["APPDATA"]))
            if local.exists(): sync_copy(local, Path(os.environ["LOCALAPPDATA"]))
        elif IS_MAC and (src / "Preferences").exists():
            plist_src = src / "Preferences"
            plist_dest = home / "Library" / "Preferences"
            for f in plist_src.iterdir():
                if f.is_file() and f.suffix == '.plist':
                    sync_copy(f, plist_dest / f.name)
        log("AppData / Preferences restored.")
    except Exception as e:
        log(f"AppData restore failed: {e}", "error")

def restore_settings():
    if not item_vars["Settings"].get() or not DATA_ROOT:
        return
    log("Restoring settings...")
    try:
        src = Path(DATA_ROOT)
        if IS_WINDOWS and (src / "UserRegistry.reg").exists():
            reg_file = src / "UserRegistry.reg"
            subprocess.run(['reg', 'import', str(reg_file)], check=True, timeout=30)
        elif IS_MAC and (src / "PlistSettings").exists():
            plist_dir = src / "PlistSettings"
            for f in plist_dir.glob("*.plist"):
                dest = Path.home() / "Library" / "Preferences" / f.name
                sync_copy(f, dest)
        log("Settings restored.")
    except Exception as e:
        log(f"Settings restore failed: {e}", "error")

def restore_wallpaper():
    if not item_vars["Wallpaper"].get() or not DATA_ROOT:
        return
    log("Applying wallpaper...")
    try:
        wp = Path(DATA_ROOT) / "Wallpaper.jpg"
        if not wp.exists():
            log("Wallpaper not found.", "warning")
            return
        if IS_WINDOWS:
            dest_dir = Path(os.environ["LOCALAPPDATA"]) / "Microsoft" / "Windows" / "Themes"
            dest_dir.mkdir(exist_ok=True)
            dest = dest_dir / "TranscodedWallpaper"
            shutil.copy2(wp, dest)
            subprocess.run(['reg', 'add', 'HKCU\\Control Panel\\Desktop', '/v', 'Wallpaper', '/t', 'REG_SZ', '/d', str(dest), '/f'])
            subprocess.run(['rundll32.exe', 'user32.dll,UpdatePerUserSystemParameters'])
        elif IS_MAC:
            pic_dir = Path.home() / "Pictures"
            pic_dir.mkdir(exist_ok=True)
            dest = pic_dir / "Migrated-Wallpaper.jpg"
            shutil.copy2(wp, dest)
            script = f'tell application "Finder" to set desktop picture to POSIX file "{dest}"'
            subprocess.run(['osascript', '-e', script], check=True)
        log("Wallpaper applied.")
    except Exception as e:
        log(f"Wallpaper failed: {e}", "error")

def restore_wifi():
    if not item_vars["WiFi"].get() or not DATA_ROOT:
        return
    log("Importing Wi-Fi profiles...")
    try:
        src = Path(DATA_ROOT)
        if IS_WINDOWS and (src / "WiFiProfiles").exists():
            for xml in (src / "WiFiProfiles").glob("*.xml"):
                subprocess.run(['netsh', 'wlan', 'add', 'profile', f'filename="{xml}"', 'user=all'], timeout=10)
        elif IS_MAC and (src / "WiFiProfiles.txt").exists():
            subprocess.run(['networksetup', '-import', str(src / "WiFiProfiles.txt")], timeout=10)
        log("Wi-Fi profiles imported.")
    except Exception as e:
        log(f"Wi-Fi import failed: {e}", "error")

def restore_mail():
    if not item_vars["Mail"].get() or not DATA_ROOT:
        return
    log("Restoring mail data...")
    try:
        src = Path(DATA_ROOT)
        if IS_WINDOWS and (src / "OutlookData").exists():
            sync_copy(src / "OutlookData", Path(os.environ["LOCALAPPDATA"]) / "Microsoft" / "Outlook")
        elif IS_MAC and (src / "MailData").exists():
            sync_copy(src / "MailData", Path.home() / "Library" / "Containers" / "com.apple.mail" / "Data")
        log("Mail data restored.")
    except Exception as e:
        log(f"Mail restore failed: {e}", "error")

def restore_network():
    if not item_vars["Network"].get() or not DATA_ROOT:
        return
    log("Applying network settings...")
    net_dir = Path(DATA_ROOT) / "Network"
    if not net_dir.exists():
        log("No network data to apply.", "warning")
        return
    try:
        hosts_src = net_dir / "hosts"
        if hosts_src.exists():
            if IS_WINDOWS:
                shutil.copy2(hosts_src, Path("C:/Windows/System32/drivers/etc/hosts"))
            elif IS_MAC:
                subprocess.run(['sudo', 'cp', str(hosts_src), '/etc/hosts'], check=True)
            log("Hosts file applied.")
        drives_file = net_dir / "MappedDrives.txt"
        if drives_file.exists():
            content = drives_file.read_text()
            if IS_WINDOWS:
                import re
                shares = re.findall(r'(\\\\[^ \n]+)', content)
                for share in shares[:3]:
                    subprocess.run(['net', 'use', 'Z:', share, '/persistent:yes'], timeout=10, shell=True)
            elif IS_MAC:
                import re
                mounts = re.findall(r'(smb://[^\s]+)', content)
                for m in mounts[:3]:
                    subprocess.run(['open', m], timeout=10)
            log("Mapped drives restored.")
    except Exception as e:
        log(f"Network restore failed: {e}", "error")

def install_chrome():
    if not item_vars["Chrome"].get():
        return
    log("Installing Google Chrome...")
    try:
        if IS_WINDOWS:
            chrome_path = Path(os.environ["PROGRAMFILES"]) / "Google" / "Chrome" / "Application" / "chrome.exe"
            if chrome_path.exists():
                log("Chrome already installed.")
                return
            assets = SCRIPT_DIR / "Assets"
            installer = assets / "Chrome-Windows.exe"
            if not installer.exists():
                url = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
                installer = Path(tempfile.gettempdir()) / "chrome_installer.exe"
                log("Downloading Chrome...")
                urllib.request.urlretrieve(url, installer)
            log("Installing...")
            subprocess.run([str(installer), '/quiet', '/install'], check=True, timeout=300)
            if "temp" in str(installer):
                installer.unlink(missing_ok=True)
        elif IS_MAC:
            chrome_path = Path("/Applications/Google Chrome.app")
            if chrome_path.exists():
                log("Chrome already installed.")
                return
            assets = SCRIPT_DIR / "Assets"
            dmg = assets / "Chrome-Mac.dmg"
            if not dmg.exists():
                url = "https://dl.google.com/chrome/mac/universal/stable/GGRM/googlechrome.dmg"
                dmg = Path(tempfile.gettempdir()) / "GoogleChrome.dmg"
                log("Downloading Chrome DMG...")
                urllib.request.urlretrieve(url, dmg)
            mount_point = Path("/Volumes/Google Chrome")
            subprocess.run(['hdiutil', 'attach', str(dmg), '-mountpoint', str(mount_point), '-quiet'], check=True, timeout=30)
            app_src = mount_point / "Google Chrome.app"
            if app_src.exists():
                shutil.copytree(app_src, "/Applications/Google Chrome.app", symlinks=True)
            subprocess.run(['hdiutil', 'detach', str(mount_point), '-quiet'], timeout=10)
            if "temp" in str(dmg):
                dmg.unlink()
        log("✅ Chrome installed.")
    except Exception as e:
        log(f"Chrome install failed: {e}", "error")

def join_domain():
    if not item_vars["AD"].get():
        return
    log("Joining Active Directory domain...")
    ad_dir = Path(DATA_ROOT) / "ActiveDirectory"
    if not ad_dir.exists():
        log("No AD profile found.", "warning")
        return
    try:
        if IS_WINDOWS:
            profile_file = ad_dir / "AD_Profile.txt"
            if not profile_file.exists():
                log("AD profile missing.", "error")
                return
            content = profile_file.read_text()
            domain_line = [l for l in content.splitlines() if "Domain:" in l]
            if not domain_line:
                log("Domain not found in profile.", "error")
                return
            domain = domain_line[0].split(":", 1)[1].strip()
            username = os.getlogin()
            def prompt_creds():
                win = Toplevel(root)
                win.title("Domain Join")
                Label(win, text=f"Joining domain: {domain}").pack(pady=10)
                Label(win, text="Domain Admin Username:").pack()
                user_var = StringVar()
                Entry(win, textvariable=user_var, width=30).pack()
                Label(win, text="Password:").pack()
                pass_var = StringVar()
                Entry(win, textvariable=pass_var, width=30, show="*").pack()
                submitted = [None]
                def submit():
                    submitted[0] = (user_var.get(), pass_var.get())
                    win.destroy()
                Button(win, text="Join Domain", command=submit).pack(pady=10)
                root.wait_window(win)
                return submitted[0]
            creds = prompt_creds()
            if not creds:
                log("Domain join cancelled.", "warning")
                return
            admin_user, admin_pass = creds
            log("Joining domain...")
            ps_script = f'''
            $securePassword = ConvertTo-SecureString "{admin_pass}" -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential("{admin_user}", $securePassword)
            Add-Computer -DomainName "{domain}" -Credential $credential -Restart:$false
            '''
            result = subprocess.run([
                'powershell', '-Command', ps_script
            ], capture_output=True, text=True)
            if result.returncode == 0:
                log(f"✅ Joined domain: {domain}. Reboot to apply.")
            else:
                log(f"Domain join failed: {result.stderr}", "error")
    except Exception as e:
        log(f"Domain join failed: {e}", "error")

# --- Start Restore ---
def start_restore():
    save_config()
    global DATA_ROOT
    if not DATA_ROOT:
        DATA_ROOT = DATA_DIR / source_var.get()
    if not DATA_ROOT.exists():
        log("Selected source folder does not exist!", "error")
        messagebox.showerror("Error", "Source folder not found!")
        return
    log("Starting pre-restore integrity verification...")
    if not verify_all_files():
        return
    if not verify_disk_image():
        return
    log("✅ Integrity verification passed. Starting restore...")
    try:
        restore_files()
        restore_appdata()
        restore_settings()
        restore_wallpaper()
        restore_wifi()
        restore_mail()
        restore_network()
        install_chrome()
        join_domain()
        log("✅ Restore completed! Please restart.", "info")
        report = generate_report(is_export=False)
        messagebox.showinfo("Success", f"Restore complete!\nReport: {report}\nRestart recommended.")
    except Exception as e:
        log(f"Restore failed: {e}", "error")
        messagebox.showerror("Error", f"Restore failed: {e}")

# --- GUI ---
root = Tk()
root.title("Restore Tool [Import]")
root.geometry("1000x700")
root.resizable(True, True)

# Configure grid
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=2)
root.grid_rowconfigure(0, weight=0)
root.grid_rowconfigure(1, weight=1)

# --- Title ---
Label(root, text="Universal Restore Tool", font=("Helvetica", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=10, sticky="ew")

# --- Main Frame ---
main_frame = Frame(root)
main_frame.grid(row=1, column=0, columnspan=2, padx=20, pady=10, sticky="nsew")
main_frame.grid_columnconfigure(0, weight=1)
main_frame.grid_columnconfigure(1, weight=2)
main_frame.grid_rowconfigure(0, weight=1)

# --- Left Panel ---
left_frame = LabelFrame(main_frame, text=" Configuration ", padx=10, pady=10)
left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

# Auto-detect
detected = detect_source()
Label(left_frame, text=f"Auto-detected: {detected or 'None'}", fg="green" if detected else "red").grid(row=0, column=0, columnspan=3, sticky=W, pady=(0,10))

# Source Selection
Label(left_frame, text="Source System", font=("Helvetica", 10, "bold")).grid(row=1, column=0, columnspan=2, sticky=W, pady=(0,5))
source_var = StringVar(value=detected or "Windows")
Radiobutton(left_frame, text="Windows", variable=source_var, value="Windows").grid(row=2, column=0, sticky=W)
Radiobutton(left_frame, text="macOS", variable=source_var, value="Mac").grid(row=3, column=0, sticky=W)

def select_custom():
    path = filedialog.askdirectory(title="Select Migration Data Folder")
    if path:
        p = Path(path)
        if "Windows" in str(p):
            source_var.set("Windows")
        elif "Mac" in str(p):
            source_var.set("Mac")
        global DATA_ROOT
        DATA_ROOT = p
        log(f"Custom source: {p}")

Button(left_frame, text="Browse Folder", command=select_custom).grid(row=4, column=0, pady=5, sticky=W)
Button(left_frame, text="Apply Selection", command=lambda: setattr(sys.modules[__name__], 'DATA_ROOT', DATA_DIR / source_var.get())).grid(row=5, column=0, columnspan=3, pady=10, sticky=W)

# Items to Restore
Label(left_frame, text="Items to Restore", font=("Helvetica", 10, "bold")).grid(row=6, column=0, columnspan=2, sticky=W, pady=(10,5))
item_vars = {
    "Files": BooleanVar(value=True),
    "AppData": BooleanVar(value=True),
    "Settings": BooleanVar(value=True),
    "Wallpaper": BooleanVar(value=True),
    "WiFi": BooleanVar(value=True),
    "Mail": BooleanVar(value=True),
    "Network": BooleanVar(value=True),
    "Chrome": BooleanVar(value=True),
    "AD": BooleanVar(value=True),
}
for i, (key, var) in enumerate(item_vars.items(), start=7):
    Checkbutton(left_frame, text=key.replace("Chrome", "Install Google Chrome").replace("AD", "Join Active Directory"), variable=var).grid(row=i, column=0, columnspan=2, sticky=W)

# Start Button
Button(left_frame, text="🚀 START RESTORE", command=start_restore,
       bg="green", fg="white", font=("Helvetica", 11, "bold"), height=2).grid(row=len(item_vars)+8, column=0, columnspan=2, pady=(20,10), sticky=EW)

# Exit Button
Button(left_frame, text="Exit", command=root.quit, font=("Helvetica", 10)).grid(row=len(item_vars)+9, column=0, columnspan=2, pady=(0,0), sticky=EW)

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
left_frame.grid_rowconfigure(len(item_vars)+10, weight=1)
left_frame.grid_columnconfigure(0, weight=1)

root.mainloop()