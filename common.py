#!/usr/bin/env python3
"""
Common utilities for Universal Migration Tool
Shared functions and constants used across migrate.py, restore.py, and verify_image.py
"""

import os
import sys
import shutil
import json
import logging
import platform
import hashlib
from datetime import datetime
from pathlib import Path
from tkinter import END

# --- OS Detection ---
OS = platform.system()
IS_WINDOWS = OS == "Windows"
IS_MAC = OS == "Darwin"

# --- Path Setup ---
def get_script_dir():
    """Get the script directory with fallback"""
    try:
        return Path(__file__).resolve().parent
    except:
        return Path(os.getcwd())

def setup_directories(script_dir):
    """Setup common directories used by migration tools"""
    data_dir = script_dir / "Data"
    logs_dir = script_dir / "Logs"
    reports_dir = script_dir / "Reports"
    
    logs_dir.mkdir(exist_ok=True)
    reports_dir.mkdir(exist_ok=True)
    (data_dir / "Windows").mkdir(exist_ok=True, parents=True)
    (data_dir / "Mac").mkdir(exist_ok=True, parents=True)
    
    return data_dir, logs_dir, reports_dir

# --- Logging Setup ---
def setup_logging(logs_dir, log_prefix="migration"):
    """Setup logging configuration"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = logs_dir / f"{log_prefix}_{timestamp}.log"
    
    logging.basicConfig(
        filename=log_path, 
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )
    
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    logging.getLogger().addHandler(console)
    
    return log_path

def create_log_function(text_widget=None, root=None):
    """Create a log function that writes to both logging and GUI"""
    def log(msg, level="info"):
        getattr(logging, level)(msg)
        if text_widget:
            text_widget.config(state="normal")
            text_widget.insert(END, msg + "\n")
            text_widget.see(END)
            text_widget.config(state="disabled")
            if root:
                root.update_idletasks()
    return log

# --- File Operations ---
def is_newer_or_different(src: Path, dest: Path) -> bool:
    """Check if source file is newer or different than destination"""
    if not dest.exists():
        return True
    try:
        src_stat = src.stat()
        dest_stat = dest.stat()
        return src_stat.st_mtime > dest_stat.st_mtime or src_stat.st_size != dest_stat.st_size
    except:
        return True

def sync_copy(src: Path, dest: Path, log_func=None):
    """Sync copy with logging support"""
    if not is_newer_or_different(src, dest):
        return
    
    if log_func:
        log_func(f"Sync: {src.name}")
    
    dest.parent.mkdir(exist_ok=True, parents=True)
    try:
        if src.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(src, dest, symlinks=True)
        else:
            shutil.copy2(src, dest)
    except Exception as e:
        if log_func:
            log_func(f"Copy failed {src} -> {dest}: {e}", "error")

def calculate_sha256(file_path, chunk_size=1 << 20):
    """Calculate SHA-256 hash of a file in chunks"""
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return None

# --- Config Management ---
def load_config(config_file, default_config=None):
    """Load configuration from JSON file with fallback to defaults"""
    if config_file.exists():
        try:
            with open(config_file) as f:
                return json.load(f)
        except Exception:
            pass
    return default_config or {}

def save_config(config_file, config_data, log_func=None):
    """Save configuration to JSON file"""
    try:
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
    except Exception as e:
        if log_func:
            log_func(f"Config save failed: {e}", "error")