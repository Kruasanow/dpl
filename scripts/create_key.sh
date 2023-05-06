#!/bin/bash
# 1 - путь, 2 - имя ключа, 3 - ключ 
touch $1/ssl_keys/$2

echo "$3" > $1/ssl_keys/$2