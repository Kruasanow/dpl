#!/bin/bash
tshark -i - < dump_input/$1 > dump_output/$2
echo "dump translated to txt ..."
