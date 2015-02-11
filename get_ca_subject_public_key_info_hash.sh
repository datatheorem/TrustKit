#!/bin/bash
PORT=$2
if [ -z "$2" ]
    then
        PORT=443
fi

echo '--------------'
echo 'CA Certificate'
echo '--------------'
CACERT=$(openssl s_client -showcerts -connect $1:$PORT < /dev/null 2>/dev/null | tail -r | grep -m 1  BEGIN -B 500 | tail -r)
echo "$CACERT" | openssl x509 -subject -issuer -fingerprint -sha1 -noout -in /dev/stdin

echo ''
echo '------------------------'
echo 'CA Subject Key Info Hash'
echo '------------------------'
echo "$CACERT" | openssl x509  -pubkey -noout -in /dev/stdin | openssl rsa -outform DER -pubin -in /dev/stdin 2>/dev/null | shasum -a 256
