#!/bin/bash
PORT=$2
if [ -z "$2" ]
    then
        PORT=443
fi

echo '----------------------------'
echo 'Top Intermediate Certificate'
echo '----------------------------'
CACERT=$(openssl s_client -showcerts -connect $1:$PORT < /dev/null 2>/dev/null | tail -r | grep -m 1  BEGIN -B 500 | tail -r)
echo "$CACERT" | openssl x509 -subject -issuer -fingerprint -sha1 -noout -in /dev/stdin

echo '--------------------------'
echo 'TrustKit Pin Configuration'
echo '--------------------------'
# Generate the Subject Public Key Info hash
pin=$(echo "$CACERT" | openssl x509  -pubkey -noout -in /dev/stdin | openssl rsa -outform DER -pubin -in /dev/stdin 2>/dev/null | openssl dgst -sha256 -binary | openssl enc -base64)
echo "kTSKPublicKeyHashes: @[\"$pin\"]"

# Generate the public key algorithm
publickey=$(echo "$CACERT" | openssl x509 -in /dev/stdin -text -noout | grep 'Public Key')
if [[ $publickey == *"4096 bit"* ]]
then
echo "kTSKPublicKeyAlgorithms: @[TSKAlgorithmRsa4096]";
elif [[ $publickey == *"2048 bit"* ]]
then
echo "kTSKPublicKeyAlgorithms: @[kTSKAlgorithmRsa2048]";
fi
