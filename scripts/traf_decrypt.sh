#!/bin/bash
# echo "параметры: 1 - дамп, 2 - файл ключа, 3 - формат [txt or pcap(ng)]"
wayAq='/home/ubuntu18/Desktop/dpl'
wayHp='/home/ubuntu18/diploma-1/dpl'
formatPCAP='-w'
time=$(date '+%Y-%m-%d_%H-%M-%S')

tshark -r $wayHp/dump_input/$1 -o "ssl.keylog_file:$wayHp/ssl_keys/$2" -o "ssl.debug_file:$wayHp/ssl_logs/pcap_$time.log" -o "ssl.desegment_ssl_records: TRUE" -o "ssl.desegment_ssl_application_data: TRUE" $formatPCAP $wayHp/dump_output/decrypted_pcap_out/decrypted_$1
# if [[ -f $wayHp/dump_output/decrypted_pcap_out/decrypted_$1 ]]; then
#     echo "Трафик успешно расшифрован в формате pcap"
# else
#     echo "Ошибка расшифровки трафика в формате pcap"
# fi
tshark -r $wayHp/dump_input/$1 -o "ssl.keylog_file:$wayHp/ssl_keys/$2" -o "ssl.debug_file:$wayHp/ssl_logs/txt_$time.log" -o "ssl.desegment_ssl_records: TRUE" -o "ssl.desegment_ssl_application_data: TRUE" > $wayHp/dump_output/decrypted_txt_out/decrypted_$1
# if [[ -f $wayHp/dump_output/decrypted_txt_out/decrypted_$1 ]]; then
#     echo "Трафик успешно расшифрован в формате txt"
# else
#     echo "Ошибка расшифровки трафика в формате txt"
# fi
# tshark -r smtp-ssl.pcapng -o "ssl.keylog_file:12.key" -o "ssl.debug_file:ssl_debug.log" -o "ssl.desegment_ssl_records: TRUE" -o "ssl.desegment_ssl_application_data: TRUE"



