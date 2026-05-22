#!/bin/sh
set -eu

CERT_DIR="/etc/nginx/ssl"
CERT_FILE="$CERT_DIR/server.crt"
KEY_FILE="$CERT_DIR/server.key"

mkdir -p "$CERT_DIR"

if [ ! -s "$CERT_FILE" ] || [ ! -s "$KEY_FILE" ]; then
  echo "[nginx-init] TLS certificate/key not found. Generating self-signed cert at $CERT_DIR"
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/CN=localhost"
  chmod 600 "$KEY_FILE"
  chmod 644 "$CERT_FILE"
fi
