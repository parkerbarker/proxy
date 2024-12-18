#!/bin/bash

# Stop on errors
set -e

# Variables
ROOT_CA_DIR="./certificates/root"
INTERMEDIATE_CA_DIR="./certificates/intermediate"
DOMAIN="test.parkerbarker.com"

# Create directories and initialize files for Root CA
mkdir -p $ROOT_CA_DIR/{certs,crl,newcerts,private}
touch $ROOT_CA_DIR/index.txt
echo 1000 > $ROOT_CA_DIR/serial

# Generate Root CA private key
echo "Generating Root CA private key..."
openssl genrsa -out $ROOT_CA_DIR/private/rootCA.key 4096

# Generate Root CA certificate
echo "Generating Root CA certificate..."
openssl req -x509 -new -nodes -key $ROOT_CA_DIR/private/rootCA.key -sha256 -days 3650 -out $ROOT_CA_DIR/certs/rootCA.crt \
  -subj "/CN=Root CA"

# Create directories and initialize files for Intermediate CA
mkdir -p $INTERMEDIATE_CA_DIR/{certs,crl,csr,newcerts,private}
touch $INTERMEDIATE_CA_DIR/index.txt
echo 1000 > $INTERMEDIATE_CA_DIR/serial
echo 1000 > $INTERMEDIATE_CA_DIR/crlnumber

# Generate Intermediate CA private key
echo "Generating Intermediate CA private key..."
openssl genrsa -out $INTERMEDIATE_CA_DIR/private/intermediateCA.key 4096

# Generate Intermediate CA CSR
echo "Generating Intermediate CA CSR..."
openssl req -new -key $INTERMEDIATE_CA_DIR/private/intermediateCA.key -out $INTERMEDIATE_CA_DIR/csr/intermediateCA.csr \
  -subj "/CN=Intermediate CA"

# Sign Intermediate CA certificate with Root CA
echo "Signing Intermediate CA certificate with Root CA..."
cat > $INTERMEDIATE_CA_DIR/v3_intermediate.ext <<EOF
basicConstraints = CA:TRUE, pathlen:0
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
authorityKeyIdentifier = keyid:always,issuer
EOF
openssl x509 -req -in $INTERMEDIATE_CA_DIR/csr/intermediateCA.csr -CA $ROOT_CA_DIR/certs/rootCA.crt \
  -CAkey $ROOT_CA_DIR/private/rootCA.key -CAcreateserial -out $INTERMEDIATE_CA_DIR/certs/intermediateCA.crt \
  -days 1825 -sha256 -extfile $INTERMEDIATE_CA_DIR/v3_intermediate.ext

# Generate private key for the domain
echo "Generating private key for $DOMAIN..."
openssl genrsa -out $INTERMEDIATE_CA_DIR/private/$DOMAIN.key 2048

# Generate CSR for the domain
echo "Generating CSR for $DOMAIN..."
openssl req -new -key $INTERMEDIATE_CA_DIR/private/$DOMAIN.key -out $INTERMEDIATE_CA_DIR/csr/$DOMAIN.csr \
  -subj "/CN=$DOMAIN"

# Sign domain CSR with Intermediate CA
echo "Signing $DOMAIN certificate with Intermediate CA..."
cat > $INTERMEDIATE_CA_DIR/v3_server.ext <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:$DOMAIN
EOF
openssl x509 -req -in $INTERMEDIATE_CA_DIR/csr/$DOMAIN.csr -CA $INTERMEDIATE_CA_DIR/certs/intermediateCA.crt \
  -CAkey $INTERMEDIATE_CA_DIR/private/intermediateCA.key -CAcreateserial -out $INTERMEDIATE_CA_DIR/certs/$DOMAIN.crt \
  -days 375 -sha256 -extfile $INTERMEDIATE_CA_DIR/v3_server.ext

# Verify the certificate chain
echo "Verifying certificate chain..."
openssl verify -CAfile <(cat $INTERMEDIATE_CA_DIR/certs/intermediateCA.crt $ROOT_CA_DIR/certs/rootCA.crt) \
  $INTERMEDIATE_CA_DIR/certs/$DOMAIN.crt

echo "Certificate Authority setup completed successfully!"