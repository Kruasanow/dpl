#!/bin/bash
echo "scr.sh: add user that u LOGGED TO wireshark group n own /usr/bin/dumpcap!!!"
rm dump_output/*
tshark -i - < dump_input/$1 > dump_output/$2
echo "scr.sh: dump translated to txt ..."
