#!/usr/bin/env python3
"""
Disk Image Integrity Verifier
Generates and verifies SHA-256 hashes for disk images
"""

import os
import sys
import hashlib
import logging
import subprocess
import platform
from datetime import datetime
from tkinter import *
from tkinter import ttk, messagebox, filedialog
from pathlib import Path

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
LOGS_DIR.mkdir(exist_ok=True)

# --- Logging ---
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_path = LOGS_DIR / f"image_verify_{timestamp}.log"
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

# --- Hashing Function ---
def calculate_sha256(file_path, chunk_size=1 << 20):
    """Calculate SHA-256 hash of a file in chunks"""
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        log(f"Read error: {e}", "error")
        return None

# --- Find Disk Images ---
def find_disk_images():
    locations = [
        DATA_DIR / "Windows" / "DiskImage",
        DATA_DIR / "Mac" / "DiskImage"
    ]
    images = []
    for loc in locations:
        if not loc.exists():
            continue
        for ext in ['*.img', '*.gz', '*.vhd', '*.vhdx', '*.dmg']:
            for img in loc.glob(ext):
                if img.is_file():
                    images.append(img)
    return images

# --- Generate or Verify Hash ---
def verify_image(img_path: Path):
    hash_file = img_path.with_suffix(img_path.suffix + ".sha256")
    if not hash_file.exists():
        log(f"No hash file found for {img_path.name}. Creating baseline...")
        digest = calculate_sha256(img_path)
        if digest:
            hash_file.write_text(f"{digest}  {img_path.name}\n")
            log(f"✅ Baseline hash created: {hash_file.name}")
        else:
            log(f"❌ Failed to hash {img_path.name}", "error")
        return False, None, digest
    expected = hash_file.read_text().split()[0].strip()
    log(f"Verifying {img_path.name}...")
    actual = calculate_sha256(img_path)
    if not actual:
        return False, expected, None
    is_valid = actual.lower() == expected.lower()
    if is_valid:
        log(f"✅ {img_path.name} — Image OK (hash matches)")
    else:
        log(f"❌ {img_path.name} — CORRUPTED! Hash mismatch", "error")
        log(f"Expected: {expected}", "error")
        log(f"Actual:   {actual}", "error")
    return is_valid, expected, actual

# --- GUI ---
root = Tk()
root.title("Image Integrity Verifier")
root.geometry("700x500")
root.resizable(False, False)

Label(root, text="Disk Image Integrity Checker", font=("Helvetica", 16, "bold")).pack(pady=10)

# Image List
list_frame = LabelFrame(root, text=" Found Disk Images ", padx=10, pady=10)
list_frame.pack(pady=10, padx=20, fill=BOTH, expand=True)
listbox = Listbox(list_frame, height=8, width=80)
scrollbar = Scrollbar(list_frame, orient=VERTICAL, command=listbox.yview)
listbox.config(yscrollcommand=scrollbar.set)
listbox.pack(side=LEFT, fill=BOTH, expand=True)
scrollbar.pack(side=RIGHT, fill=Y)

# Log Box
log_frame = LabelFrame(root, text=" Verification Log ", padx=10, pady=10)
log_frame.pack(pady=10, padx=20, fill=BOTH, expand=True)
text_widget = Text(log_frame, height=10, state="disabled", font=("Courier", 9))
text_widget.pack(fill=BOTH, expand=True)

# --- Refresh List ---
def refresh_images():
    listbox.delete(0, END)
    images = find_disk_images()
    if not images:
        listbox.insert(END, "No disk images found in /Data/*/DiskImage")
        log("No disk images found.", "warning")
    else:
        for img in images:
            listbox.insert(END, str(img.relative_to(SCRIPT_DIR)))
    log(f"Found {len(images)} disk image(s).")

# --- Verify Selected ---
def verify_selected():
    selection = listbox.curselection()
    if not selection:
        messagebox.showinfo("No Selection", "Please select an image to verify.")
        return
    idx = selection[0]
    img_path = Path(listbox.get(idx))
    if not img_path.is_absolute():
        img_path = SCRIPT_DIR / img_path
    if not img_path.exists():
        log(f"File not found: {img_path}", "error")
        return
    verify_image(img_path)

# --- Verify All ---
def verify_all():
    images = find_disk_images()
    if not images:
        messagebox.showinfo("No Images", "No disk images found to verify.")
        return
    log(f"Starting verification of {len(images)} image(s)...")
    results = []
    for img in images:
        ok, expected, actual = verify_image(img)
        results.append((img.name, ok))
    good = sum(1 for r in results if r[1])
    bad = len(results) - good
    log(f"🔍 Verification complete: {good} OK, {bad} corrupted", "info" if bad == 0 else "error")
    if bad == 0:
        messagebox.showinfo("Success", f"All {good} images are intact.")
    else:
        messagebox.showerror("Integrity Check Failed", f"{bad} image(s) are corrupted!")

# --- Buttons ---
btn_frame = Frame(root)
btn_frame.pack(pady=10)
Button(btn_frame, text="Refresh Images", command=refresh_images).pack(side=LEFT, padx=5)
Button(btn_frame, text="Verify Selected", command=verify_selected).pack(side=LEFT, padx=5)
Button(btn_frame, text="Verify All", bg="green", fg="white", command=verify_all).pack(side=LEFT, padx=5)
Button(btn_frame, text="Exit", command=root.quit).pack(side=LEFT, padx=5)

# --- Auto-refresh on startup ---
refresh_images()

root.mainloop()