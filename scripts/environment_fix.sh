#!/bin/bash
rm -r __pycache__/
export DB_USERNAME='ubuntu18'
export DB_PASSWORD='rusanow'
python3 db_do/init_db.py
echo "[*]environment.sh: database refreshed"
