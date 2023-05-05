#!/bin/bash
echo "параметры: 1 - дамп, 2 - файл ключа, 3 - tls или ssl "
tshark -r /home/ubuntu18/Desktop/dpl/dump_input/$1 -o "ssl.keylog_file:/home/ubuntu18/Desktop/dpl/dump_input/keys/$2" -o "ssl.debug_file:/home/ubuntu18/Desktop/dpl/dump_input/ssl_logs/$3" -o "ssl.desegment_ssl_records: TRUE" -o "ssl.desegment_ssl_application_data: TRUE" -w  /home/ubuntu18/Desktop/dpl/$4
#tshark -r smtp-ssl.pcapng -o "ssl.keylog_file:12.key" -o "ssl.debug_file:ssl_debug.log" -o "ssl.desegment_ssl_records: TRUE" -o "ssl.desegment_ssl_application_data: TRUE"



