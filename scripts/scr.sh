#!/bin/bash
echo "[*]scr.sh: add user that u LOGGED TO wireshark group n own /usr/bin/dumpcap!!!"
rm dump_output/out.txt
rm dump_output/decrypted_*_out/*
tshark -i - < dump_input/$1 > dump_output/$2
echo "[*]scr.sh: dump translated to txt ..."
