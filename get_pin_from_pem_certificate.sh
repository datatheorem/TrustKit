#!/bin/bash
CERT=$1
if [ -z "$1" ]
    then
        echo 'Error: no certificate provided'
        exit
fi

echo '-----------'
echo 'Certificate'
echo '-----------'
openssl x509 -subject -issuer -fingerprint -sha1 -noout -in $CERT


echo '---------------------'
echo 'Subject Key Info Pin'
echo '---------------------'
openssl x509  -pubkey -noout -in $CERT | openssl rsa -outform DER -pubin -in /dev/stdin 2>/dev/null | openssl dgst -sha256 -binary | openssl enc -base64
