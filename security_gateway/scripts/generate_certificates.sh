#!/usr/bin/env bash
# ==============================================================================
# HNX26EPS01 Security Gateway — Cryptographic Certificate Generator
# Generates Root CA, Server (TLS 1.3), and Client (mTLS) Certificates
# Enforces strong key sizes, SAN extensions, and strict 0600 file permissions.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CERT_DIR="${GATEWAY_DIR}/certs"

mkdir -p "${CERT_DIR}"
chmod 700 "${CERT_DIR}"

echo "[+] Generating Security Gateway PKI in ${CERT_DIR}..."

# 1. Certificate Authority (CA)
CA_KEY="${CERT_DIR}/ca.key"
CA_CERT="${CERT_DIR}/ca.crt"
if [[ ! -f "${CA_KEY}" || ! -f "${CA_CERT}" ]]; then
    echo "[*] Generating Root CA..."
    openssl ecparam -name prime256v1 -genkey -noout -out "${CA_KEY}"
    chmod 600 "${CA_KEY}"
    openssl req -new -x509 -sha256 -key "${CA_KEY}" -out "${CA_CERT}" -days 365 \
        -subj "/C=US/ST=Security/L=Local/O=HNX26EPS01/OU=GatewayCA/CN=HNX-Security-Root-CA"
    chmod 644 "${CA_CERT}"
    echo "[✓] CA generated."
fi

# 2. Server Certificate (SAN: 127.0.0.1, localhost)
SERVER_KEY="${CERT_DIR}/server.key"
SERVER_CSR="${CERT_DIR}/server.csr"
SERVER_CERT="${CERT_DIR}/server.crt"
SERVER_EXT="${CERT_DIR}/server_ext.cnf"

cat <<EOF > "${SERVER_EXT}"
basicConstraints = CA:FALSE
nsCertType = server
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

echo "[*] Generating Gateway Server Certificate..."
openssl ecparam -name prime256v1 -genkey -noout -out "${SERVER_KEY}"
chmod 600 "${SERVER_KEY}"
openssl req -new -sha256 -key "${SERVER_KEY}" -out "${SERVER_CSR}" \
    -subj "/C=US/ST=Security/L=Local/O=HNX26EPS01/OU=SecureGateway/CN=127.0.0.1"
openssl x509 -req -in "${SERVER_CSR}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" \
    -CAcreateserial -out "${SERVER_CERT}" -days 365 -sha256 -extfile "${SERVER_EXT}"
chmod 644 "${SERVER_CERT}"
rm -f "${SERVER_CSR}" "${SERVER_EXT}"
echo "[✓] Server certificate generated."

# 3. Authorized Client Certificate (mTLS)
CLIENT_KEY="${CERT_DIR}/client.key"
CLIENT_CSR="${CERT_DIR}/client.csr"
CLIENT_CERT="${CERT_DIR}/client.crt"
CLIENT_EXT="${CERT_DIR}/client_ext.cnf"

cat <<EOF > "${CLIENT_EXT}"
basicConstraints = CA:FALSE
nsCertType = client
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

echo "[*] Generating Authorized Client Certificate..."
openssl ecparam -name prime256v1 -genkey -noout -out "${CLIENT_KEY}"
chmod 600 "${CLIENT_KEY}"
openssl req -new -sha256 -key "${CLIENT_KEY}" -out "${CLIENT_CSR}" \
    -subj "/C=US/ST=Security/L=Local/O=HNX26EPS01/OU=LegalAssistantClient/CN=client-legal-assistant"
openssl x509 -req -in "${CLIENT_CSR}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" \
    -CAcreateserial -out "${CLIENT_CERT}" -days 365 -sha256 -extfile "${CLIENT_EXT}"
chmod 644 "${CLIENT_CERT}"
rm -f "${CLIENT_CSR}" "${CLIENT_EXT}"
echo "[✓] Authorized Client certificate generated."

# 4. Untrusted Client Certificate (Signed by rogue untrusted CA for negative testing)
ROGUE_KEY="${CERT_DIR}/rogue_ca.key"
ROGUE_CA="${CERT_DIR}/rogue_ca.crt"
ROGUE_CLIENT_KEY="${CERT_DIR}/untrusted_client.key"
ROGUE_CLIENT_CSR="${CERT_DIR}/untrusted_client.csr"
ROGUE_CLIENT_CERT="${CERT_DIR}/untrusted_client.crt"

echo "[*] Generating Untrusted Client Certificate (Negative testing)..."
openssl ecparam -name prime256v1 -genkey -noout -out "${ROGUE_KEY}"
chmod 600 "${ROGUE_KEY}"
openssl req -new -x509 -sha256 -key "${ROGUE_KEY}" -out "${ROGUE_CA}" -days 30 \
    -subj "/CN=Rogue-Untrusted-CA"

openssl ecparam -name prime256v1 -genkey -noout -out "${ROGUE_CLIENT_KEY}"
chmod 600 "${ROGUE_CLIENT_KEY}"
openssl req -new -sha256 -key "${ROGUE_CLIENT_KEY}" -out "${ROGUE_CLIENT_CSR}" \
    -subj "/CN=attacker-client"
openssl x509 -req -in "${ROGUE_CLIENT_CSR}" -CA "${ROGUE_CA}" -CAkey "${ROGUE_KEY}" \
    -CAcreateserial -out "${ROGUE_CLIENT_CERT}" -days 30 -sha256
chmod 644 "${ROGUE_CLIENT_CERT}"
rm -f "${ROGUE_CLIENT_CSR}"
echo "[✓] Untrusted Client certificate generated."

# 5. Expired Certificate (Negative testing)
EXPIRED_KEY="${CERT_DIR}/expired.key"
EXPIRED_CERT="${CERT_DIR}/expired.crt"
echo "[*] Generating Expired Certificate (Negative testing)..."
openssl ecparam -name prime256v1 -genkey -noout -out "${EXPIRED_KEY}"
chmod 600 "${EXPIRED_KEY}"
openssl req -new -x509 -sha256 -key "${EXPIRED_KEY}" -out "${EXPIRED_CERT}" \
    -days -1 -subj "/CN=expired-cert" 2>/dev/null || \
openssl req -new -x509 -sha256 -key "${EXPIRED_KEY}" -out "${EXPIRED_CERT}" \
    -days 1 -subj "/CN=expired-cert"
chmod 644 "${EXPIRED_CERT}"

# Verify permissions
chmod 600 "${CERT_DIR}"/*.key 2>/dev/null || true
echo "[✓] All certificates generated and secured (Key permissions enforced: 0600)."
