#!/bin/bash
rm -r __pycache__/
export DB_USERNAME='ubuntu18'
export DB_PASSWORD='rusanow'
python3 init_db.py
echo "database refreshed, it's ok"