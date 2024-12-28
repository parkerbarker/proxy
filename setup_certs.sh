# !/bin/bash

# Stop on errors
set -e

# Required OpenSSL version for QUIC
REQUIRED_OPENSSL_VERSION="3.0.0"

# Check OpenSSL version
current_version=$(openssl version | awk '{print $2}')
if [[ "$(printf '%s\n' "$REQUIRED_OPENSSL_VERSION" "$current_version" | sort -V | head -n1)" != "$REQUIRED_OPENSSL_VERSION" ]]; then
  echo "Error: OpenSSL version $REQUIRED_OPENSSL_VERSION or higher is required for QUIC support."
  echo "Current version: $current_version"
  echo "Please upgrade OpenSSL to enable QUIC support."
  exit 1
fi
echo "OpenSSL version $current_version meets the required version $REQUIRED_OPENSSL_VERSION for QUIC support."

# Base directory for certificates
CERT_DIR="./certificates"
ROOT_CA_DIR="$CERT_DIR/root"
INTERMEDIATE_CA_DIR="$CERT_DIR/intermediate"

# Create directories for Root and Intermediate CA
mkdir -p $ROOT_CA_DIR/{certs,crl,newcerts,private}
mkdir -p $INTERMEDIATE_CA_DIR/{certs,crl,csr,newcerts,private}

# Initialize files for Root CA
touch $ROOT_CA_DIR/index.txt
echo 1000 > $ROOT_CA_DIR/serial

# Initialize files for Intermediate CA
touch $INTERMEDIATE_CA_DIR/index.txt
echo 1000 > $INTERMEDIATE_CA_DIR/serial
echo 1000 > $INTERMEDIATE_CA_DIR/crlnumber

# Generate Root CA private key
if [[ ! -f "$ROOT_CA_DIR/private/rootCA.key" ]]; then
  echo "Generating Root CA private key..."
  openssl genrsa -out "$ROOT_CA_DIR/private/rootCA.key" 4096
else
  echo "Root CA private key already exists."
fi

# Generate Root CA certificate
if [[ ! -f "$ROOT_CA_DIR/certs/rootCA.crt" ]]; then
  echo "Generating Root CA certificate..."
  openssl req -x509 -new -nodes -key "$ROOT_CA_DIR/private/rootCA.key" -sha256 -days 3650 -out "$ROOT_CA_DIR/certs/rootCA.crt" \
    -subj "/CN=Root CA"
else
  echo "Root CA certificate already exists."
fi

# Generate Intermediate CA private key
if [[ ! -f "$INTERMEDIATE_CA_DIR/private/intermediateCA.key" ]]; then
  echo "Generating Intermediate CA private key..."
  openssl genrsa -out "$INTERMEDIATE_CA_DIR/private/intermediateCA.key" 4096
else
  echo "Intermediate CA private key already exists."
fi

# Generate Intermediate CA CSR
if [[ ! -f "$INTERMEDIATE_CA_DIR/csr/intermediateCA.csr" ]]; then
  echo "Generating Intermediate CA CSR..."
  openssl req -new -key "$INTERMEDIATE_CA_DIR/private/intermediateCA.key" -out "$INTERMEDIATE_CA_DIR/csr/intermediateCA.csr" \
    -subj "/CN=Intermediate CA"
else
  echo "Intermediate CA CSR already exists."
fi

# Sign Intermediate CA certificate with Root CA
if [[ ! -f "$INTERMEDIATE_CA_DIR/certs/intermediateCA.crt" ]]; then
  echo "Signing Intermediate CA certificate with Root CA..."
  cat > $INTERMEDIATE_CA_DIR/v3_intermediate.ext <<EOF
basicConstraints = CA:TRUE, pathlen:0
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
authorityKeyIdentifier = keyid:always,issuer
EOF
  openssl x509 -req -in "$INTERMEDIATE_CA_DIR/csr/intermediateCA.csr" -CA "$ROOT_CA_DIR/certs/rootCA.crt" \
    -CAkey "$ROOT_CA_DIR/private/rootCA.key" -CAcreateserial -out "$INTERMEDIATE_CA_DIR/certs/intermediateCA.crt" \
    -days 1825 -sha256 -extfile "$INTERMEDIATE_CA_DIR/v3_intermediate.ext"
else
  echo "Intermediate CA certificate already exists."
fi

# Verify the Intermediate CA certificate chain
echo "Verifying Intermediate CA chain..."
openssl verify -CAfile "$ROOT_CA_DIR/certs/rootCA.crt" "$INTERMEDIATE_CA_DIR/certs/intermediateCA.crt"

echo "Certificate setup completed successfully!"