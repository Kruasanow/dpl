#!/bin/bash
rm -r __pycache__/
rm -rf static/*.png
export DB_USERNAME='ubuntu18'
export DB_PASSWORD='rusanow'
export PYTHONPATH=~/diploma_v1/dpl
python3 db_do/init_db.py
echo "[*]environment.sh: database refreshed"
