#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <certificate file, PEM or DER>" >&2
    exit 1
fi

# The LibreSSL that ships with macOS doesn't detect DER input on its own
FORMAT=PEM
openssl x509 -inform PEM -in "$1" -noout 2>/dev/null || FORMAT=DER

PIN="$(openssl x509 -inform "$FORMAT" -in "$1" -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary \
    | openssl enc -base64)"
echo "$PIN"
