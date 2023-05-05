#!/bin/bash
openssl pkcs12 -export -inkey $1.key -in $2.crt -out $3.p12