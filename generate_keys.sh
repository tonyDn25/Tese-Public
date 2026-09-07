#!/bin/bash

# GPS Thesis - ECDSA Key Generation
# Generates P-256 (secp256r1) key pair for signing

set -e  # Exit on error

echo "Generating ECDSA P-256 key pair..."

# Generate private key
openssl ecparam -genkey -name prime256v1 \
  -out nginx/keys/nginx_private.pem

echo "Private key generated: nginx/keys/nginx_private.pem"

# Extract public key
openssl ec -in nginx/keys/nginx_private.pem \
  -pubout -out nginx/keys/nginx_public.pem

echo "Public key generated: nginx/keys/nginx_public.pem"

# Set restrictive permissions on private key
chmod 600 nginx/keys/nginx_private.pem
chmod 644 nginx/keys/nginx_public.pem

echo ""
echo "Key generation complete"
echo ""
echo "Private key: nginx/keys/nginx_private.pem"
echo "Public key:  nginx/keys/nginx_public.pem"
