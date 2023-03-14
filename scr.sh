#!/bin/bash
echo "add user that u LOGGED TO wireshark group n own /usr/bin/dumpcap!!!"
rm dump_output/*
tshark -i - < dump_input/$1 > dump_output/$2
echo "dump translated to txt ..."
