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
openssl x509 -subject -issuer -fingerprint -sha1 -noout -inform DER -in $CERT


echo '--------------------------'
echo 'TrustKit Pin Configuration'
echo '--------------------------'

# Generate the Subject Public Key Info hash
pin=$(openssl x509  -pubkey -noout -inform DER -in $CERT | openssl rsa -outform DER -pubin -in /dev/stdin 2>/dev/null | openssl dgst -sha256 -binary | openssl enc -base64)

echo "kTSKPublicKeyHashes: @[@\"$pin\"]"

# Generate the public key algorithm
publickey=$(openssl x509 -in $CERT -inform DER -text -noout | grep 'Public Key')
if [[ $publickey == *"4096 bit"* ]]
then
echo "kTSKPublicKeyAlgorithms: @[TSKAlgorithmRsa4096]";
elif [[ $publickey == *"2048 bit"* ]]
then
echo "kTSKPublicKeyAlgorithms: @[kTSKAlgorithmRsa2048]";
fi
