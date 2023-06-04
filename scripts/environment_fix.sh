#!/bin/bash
rm -r __pycache__/
export DB_USERNAME='ubuntu18'
export DB_PASSWORD='password1234'
export PYTHONPATH=~/diploma-1/dpl
python3 db_do/init_db.py
echo "[*]environment.sh: database refreshed"
