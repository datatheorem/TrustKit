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

DER="$(mktemp)"
trap 'rm -f "$DER"' EXIT
openssl x509 -inform "$FORMAT" -in "$1" -outform DER -out "$DER"

# TrustKit hashes the Subject Public Key Info exactly as the certificate encodes it; re-encoding the key with
# `openssl pkey` can change those bytes. It is tbsCertificate's 7th field, or its 6th without the optional version.
read -r OFFSET LENGTH < <(openssl asn1parse -inform DER -in "$DER" \
    | sed -E 's/^ *([0-9]+):d=([0-9]+) +hl= *([0-9]+) +l= *([0-9]+) +(.*)$/\1 \2 \3 \4 \5/' \
    | awk '$2 == 2 { n++; if (n == 1 && /cont \[ 0 \]/) skip = 1; if (n == 6 + skip) { if (/SEQUENCE/) print $1, $3 + $4; exit } }')

PIN="$(tail -c +$((OFFSET + 1)) "$DER" | head -c "$LENGTH" \
    | openssl dgst -sha256 -binary \
    | openssl enc -base64)"
echo "$PIN"
