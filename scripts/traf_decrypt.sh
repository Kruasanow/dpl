#!/bin/bash
# echo "параметры: 1 - дамп, 2 - файл ключа, 3 - формат [txt or pcap(ng)], 4 - путь"
wayAq='/home/ubuntu18/Desktop/dpl'
wayHp='/home/ubuntu18/diploma-1/dpl'
formatPCAP='-w'
time=$(date '+%Y-%m-%d_%H-%M-%S')

tshark -r $3/dump_input/$1 -o "ssl.keylog_file:$3/ssl_keys/$2" -o "ssl.debug_file:$3/ssl_logs/pcap_log/pcap_$time.log" -o "ssl.desegment_ssl_records: TRUE" -o "ssl.desegment_ssl_application_data: TRUE" $formatPCAP $3/dump_output/decrypted_pcap_out/decrypted_$1
tshark -r $3/dump_input/$1 -o "ssl.keylog_file:$3/ssl_keys/$2" -o "ssl.debug_file:$3/ssl_logs/txt_log/txt_$time.log" -o "ssl.desegment_ssl_records: TRUE" -o "ssl.desegment_ssl_application_data: TRUE" > $3/dump_output/decrypted_txt_out/decrypted_$1