#!/usr/bin/env bash
# HTTPie wrapper that routes through the mindgame proxy.
# Usage: ./wrapper.sh GET https://example.com/api X-Reason:"looking up docs"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CA_CERT="$SCRIPT_DIR/ca.pem"

if [ ! -f "$CA_CERT" ]; then
    echo "CA cert not found at $CA_CERT" >&2
    echo "Fetch it: curl http://localhost:2080/ca.pem -o $CA_CERT" >&2
    exit 1
fi

export http_proxy=http://localhost:2080
export https_proxy=http://localhost:2080
export SSL_CERT_FILE="$CA_CERT"
export REQUESTS_CA_BUNDLE="$CA_CERT"

exec http --verify="$CA_CERT" "$@"
