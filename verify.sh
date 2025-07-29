#!/bin/bash
cd "$(dirname "$0")"
python3 ./verify_image.py
read -p "Press Enter to exit..."