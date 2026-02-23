#!/usr/bin/env bash
set -euo pipefail

OUT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/crypto"
rm -rf "$OUT"
mkdir -p "$OUT"

echo "==> Generating test crypto files in $OUT"

# ---------------------------------------------------------------------------
# 1. RSA keys (various sizes)
# ---------------------------------------------------------------------------
for bits in 1024 2048 4096; do
  openssl genrsa -out "$OUT/rsa-${bits}.key" "$bits" 2>/dev/null
  openssl rsa -in "$OUT/rsa-${bits}.key" -pubout -out "$OUT/rsa-${bits}.pub" 2>/dev/null
done

# RSA key encrypted with passphrase
openssl genrsa -aes256 -passout pass:test1234 -out "$OUT/rsa-2048-encrypted.key" 2048 2>/dev/null

# PKCS#8 encoded private key
openssl pkcs8 -topk8 -nocrypt -in "$OUT/rsa-2048.key" -out "$OUT/rsa-2048-pkcs8.key" 2>/dev/null

# PKCS#8 encrypted private key
openssl pkcs8 -topk8 -v2 aes-256-cbc -passout pass:test1234 \
  -in "$OUT/rsa-2048.key" -out "$OUT/rsa-2048-pkcs8-encrypted.key" 2>/dev/null

# ---------------------------------------------------------------------------
# 2. EC keys (various curves)
# ---------------------------------------------------------------------------
for curve in prime256v1 secp384r1 secp521r1; do
  openssl ecparam -genkey -name "$curve" -noout -out "$OUT/ec-${curve}.key" 2>/dev/null
  openssl ec -in "$OUT/ec-${curve}.key" -pubout -out "$OUT/ec-${curve}.pub" 2>/dev/null
done

# ---------------------------------------------------------------------------
# 3. Ed25519 / Ed448 keys
# ---------------------------------------------------------------------------
openssl genpkey -algorithm Ed25519 -out "$OUT/ed25519.key" 2>/dev/null
openssl pkey -in "$OUT/ed25519.key" -pubout -out "$OUT/ed25519.pub" 2>/dev/null

openssl genpkey -algorithm Ed448 -out "$OUT/ed448.key" 2>/dev/null
openssl pkey -in "$OUT/ed448.key" -pubout -out "$OUT/ed448.pub" 2>/dev/null

# ---------------------------------------------------------------------------
# 4. Self-signed CA certificate (RSA)
# ---------------------------------------------------------------------------
openssl req -new -x509 -key "$OUT/rsa-4096.key" -sha256 -days 3650 \
  -subj "/C=US/ST=California/L=San Francisco/O=Disco CA/OU=Root/CN=Disco Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out "$OUT/ca-root.pem" 2>/dev/null

# ---------------------------------------------------------------------------
# 5. Intermediate CA (RSA, signed by root)
# ---------------------------------------------------------------------------
openssl req -new -key "$OUT/rsa-2048.key" \
  -subj "/C=US/ST=California/O=Disco CA/OU=Intermediate/CN=Disco Intermediate CA" \
  -out "$OUT/ca-intermediate.csr" 2>/dev/null

openssl x509 -req -in "$OUT/ca-intermediate.csr" -CA "$OUT/ca-root.pem" -CAkey "$OUT/rsa-4096.key" \
  -CAcreateserial -days 1825 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always") \
  -out "$OUT/ca-intermediate.pem" 2>/dev/null

# ---------------------------------------------------------------------------
# 6. Leaf certificate — web server (RSA, many SANs)
# ---------------------------------------------------------------------------
openssl req -new -key "$OUT/rsa-2048.key" \
  -subj "/C=US/ST=California/L=San Francisco/O=Disco Inc/CN=disco.example.com" \
  -out "$OUT/server-rsa.csr" 2>/dev/null

openssl x509 -req -in "$OUT/server-rsa.csr" -CA "$OUT/ca-intermediate.pem" -CAkey "$OUT/rsa-2048.key" \
  -CAcreateserial -days 365 -sha256 \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:disco.example.com,DNS:*.disco.example.com,DNS:localhost,IP:127.0.0.1,IP:::1,email:admin@disco.example.com\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always") \
  -out "$OUT/server-rsa.crt" 2>/dev/null

# ---------------------------------------------------------------------------
# 7. Leaf certificate — EC key
# ---------------------------------------------------------------------------
openssl req -new -key "$OUT/ec-prime256v1.key" \
  -subj "/C=DE/O=Disco GmbH/CN=ec.disco.example.com" \
  -out "$OUT/server-ec.csr" 2>/dev/null

openssl x509 -req -in "$OUT/server-ec.csr" -CA "$OUT/ca-intermediate.pem" -CAkey "$OUT/rsa-2048.key" \
  -CAcreateserial -days 365 -sha256 \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:ec.disco.example.com\nsubjectKeyIdentifier=hash") \
  -out "$OUT/server-ec.crt" 2>/dev/null

# ---------------------------------------------------------------------------
# 8. Client authentication certificate
# ---------------------------------------------------------------------------
openssl req -new -key "$OUT/ec-secp384r1.key" \
  -subj "/C=US/O=Disco Inc/OU=Engineering/CN=alice@disco.example.com" \
  -out "$OUT/client.csr" 2>/dev/null

openssl x509 -req -in "$OUT/client.csr" -CA "$OUT/ca-intermediate.pem" -CAkey "$OUT/rsa-2048.key" \
  -CAcreateserial -days 365 -sha256 \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=email:alice@disco.example.com\nsubjectKeyIdentifier=hash") \
  -out "$OUT/client.crt" 2>/dev/null

# ---------------------------------------------------------------------------
# 9. Code signing certificate
# ---------------------------------------------------------------------------
openssl req -new -key "$OUT/rsa-2048.key" \
  -subj "/C=US/O=Disco Inc/OU=Release Engineering/CN=Disco Code Signing" \
  -out "$OUT/codesign.csr" 2>/dev/null

openssl x509 -req -in "$OUT/codesign.csr" -CA "$OUT/ca-root.pem" -CAkey "$OUT/rsa-4096.key" \
  -CAcreateserial -days 730 -sha256 \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\nsubjectKeyIdentifier=hash") \
  -out "$OUT/codesign.crt" 2>/dev/null

# ---------------------------------------------------------------------------
# 10. Email / S/MIME certificate
# ---------------------------------------------------------------------------
openssl req -new -key "$OUT/ec-prime256v1.key" \
  -subj "/C=US/O=Disco Inc/CN=bob@disco.example.com" \
  -out "$OUT/email.csr" 2>/dev/null

openssl x509 -req -in "$OUT/email.csr" -CA "$OUT/ca-root.pem" -CAkey "$OUT/rsa-4096.key" \
  -CAcreateserial -days 365 -sha256 \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=emailProtection\nsubjectAltName=email:bob@disco.example.com\nsubjectKeyIdentifier=hash") \
  -out "$OUT/email.crt" 2>/dev/null

# ---------------------------------------------------------------------------
# 11. OCSP signing certificate
# ---------------------------------------------------------------------------
openssl req -new -key "$OUT/rsa-2048.key" \
  -subj "/C=US/O=Disco CA/CN=Disco OCSP Responder" \
  -out "$OUT/ocsp.csr" 2>/dev/null

openssl x509 -req -in "$OUT/ocsp.csr" -CA "$OUT/ca-root.pem" -CAkey "$OUT/rsa-4096.key" \
  -CAcreateserial -days 365 -sha256 \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=OCSPSigning\nnoCheck=ignored\nsubjectKeyIdentifier=hash") \
  -out "$OUT/ocsp.crt" 2>/dev/null

# ---------------------------------------------------------------------------
# 12. Timestamping certificate
# ---------------------------------------------------------------------------
openssl req -new -key "$OUT/rsa-2048.key" \
  -subj "/C=US/O=Disco Inc/CN=Disco Timestamping" \
  -out "$OUT/timestamp.csr" 2>/dev/null

openssl x509 -req -in "$OUT/timestamp.csr" -CA "$OUT/ca-root.pem" -CAkey "$OUT/rsa-4096.key" \
  -CAcreateserial -days 365 -sha256 \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=timeStamping\nsubjectKeyIdentifier=hash") \
  -out "$OUT/timestamp.crt" 2>/dev/null

# ---------------------------------------------------------------------------
# 13. Expired certificate
# ---------------------------------------------------------------------------
openssl req -new -x509 -key "$OUT/rsa-2048.key" -sha256 -days 1 \
  -subj "/C=US/O=Disco Inc/CN=expired.disco.example.com" \
  -addext "subjectAltName=DNS:expired.disco.example.com" \
  -out "$OUT/expired.pem" 2>/dev/null
# Backdate it so it's already expired
faketime="$(date -d '-2 days' '+%y%m%d%H%M%SZ' 2>/dev/null || date -v-2d '+%y%m%d%H%M%SZ' 2>/dev/null || true)"
if [ -n "$faketime" ]; then
  openssl req -new -x509 -key "$OUT/rsa-2048.key" -sha256 \
    -not_before "20230101000000Z" -not_after "20230102000000Z" \
    -subj "/C=US/O=Disco Inc/CN=expired.disco.example.com" \
    -addext "subjectAltName=DNS:expired.disco.example.com" \
    -out "$OUT/expired.pem" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 14. Cert expiring very soon (within 30 days)
# ---------------------------------------------------------------------------
openssl req -new -x509 -key "$OUT/rsa-2048.key" -sha256 -days 15 \
  -subj "/C=US/O=Disco Inc/CN=expiring-soon.disco.example.com" \
  -addext "subjectAltName=DNS:expiring-soon.disco.example.com" \
  -out "$OUT/expiring-soon.pem" 2>/dev/null

# ---------------------------------------------------------------------------
# 15. Very long validity (100 years, like some embedded certs)
# ---------------------------------------------------------------------------
openssl req -new -x509 -key "$OUT/rsa-2048.key" -sha256 -days 36500 \
  -subj "/C=US/O=Disco Inc/CN=long-lived.disco.example.com" \
  -out "$OUT/long-lived.pem" 2>/dev/null

# ---------------------------------------------------------------------------
# 16. Certificate with many extensions and long subject
# ---------------------------------------------------------------------------
openssl req -new -x509 -key "$OUT/rsa-2048.key" -sha256 -days 365 \
  -subj "/C=US/ST=California/L=San Francisco/O=Disco International Holdings Inc/OU=Platform Engineering/OU=Security Team/CN=complex.disco.example.com/serialNumber=ABC123/emailAddress=complex@disco.example.com" \
  -addext "subjectAltName=DNS:complex.disco.example.com,DNS:complex2.disco.example.com,DNS:complex3.disco.example.com,IP:10.0.0.1,IP:10.0.0.2,IP:192.168.1.1,email:complex@disco.example.com,email:alt@disco.example.com" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment,dataEncipherment,keyAgreement" \
  -addext "extendedKeyUsage=serverAuth,clientAuth,codeSigning,emailProtection,timeStamping" \
  -out "$OUT/complex.pem" 2>/dev/null

# ---------------------------------------------------------------------------
# 17. Certificate chain bundle (leaf + intermediate + root in one file)
# ---------------------------------------------------------------------------
cat "$OUT/server-rsa.crt" "$OUT/ca-intermediate.pem" "$OUT/ca-root.pem" > "$OUT/chain-bundle.pem"

# ---------------------------------------------------------------------------
# 18. Multiple unrelated certs in one file
# ---------------------------------------------------------------------------
cat "$OUT/server-rsa.crt" "$OUT/server-ec.crt" "$OUT/client.crt" > "$OUT/multi-cert.pem"

# ---------------------------------------------------------------------------
# 19. CSR files (Certificate Signing Requests)
# ---------------------------------------------------------------------------
# RSA CSR
openssl req -new -key "$OUT/rsa-2048.key" \
  -subj "/C=US/O=Disco Inc/CN=csr-test.disco.example.com" \
  -addext "subjectAltName=DNS:csr-test.disco.example.com,DNS:www.csr-test.disco.example.com" \
  -out "$OUT/request-rsa.csr" 2>/dev/null

# EC CSR
openssl req -new -key "$OUT/ec-prime256v1.key" \
  -subj "/C=US/O=Disco Inc/CN=csr-ec.disco.example.com" \
  -out "$OUT/request-ec.csr" 2>/dev/null

# Ed25519 CSR
openssl req -new -key "$OUT/ed25519.key" \
  -subj "/C=US/O=Disco Inc/CN=csr-ed25519.disco.example.com" \
  -out "$OUT/request-ed25519.csr" 2>/dev/null

# ---------------------------------------------------------------------------
# 20. DER-encoded certificate (binary, not PEM)
# ---------------------------------------------------------------------------
openssl x509 -in "$OUT/server-rsa.crt" -outform DER -out "$OUT/server-rsa.der.cer" 2>/dev/null

# ---------------------------------------------------------------------------
# 21. PKCS#12 / PFX bundle (cert + key + chain)
# ---------------------------------------------------------------------------
openssl pkcs12 -export -passout pass:test1234 \
  -inkey "$OUT/rsa-2048.key" \
  -in "$OUT/server-rsa.crt" \
  -certfile "$OUT/ca-intermediate.pem" \
  -out "$OUT/server-bundle.p12" 2>/dev/null

# PKCS#12 with no password
openssl pkcs12 -export -passout pass: \
  -inkey "$OUT/ec-prime256v1.key" \
  -in "$OUT/server-ec.crt" \
  -out "$OUT/server-ec-nopass.p12" 2>/dev/null

# ---------------------------------------------------------------------------
# 22. CRL (Certificate Revocation List)
# ---------------------------------------------------------------------------
# Create a minimal openssl CA database for CRL generation
TMPCA=$(mktemp -d)
touch "$TMPCA/index.txt"
echo "01" > "$TMPCA/crlnumber"
cat > "$TMPCA/ca.cnf" <<CACNF
[ca]
default_ca = CA_default
[CA_default]
database = $TMPCA/index.txt
crlnumber = $TMPCA/crlnumber
default_md = sha256
default_crl_days = 30
CACNF

openssl ca -gencrl -config "$TMPCA/ca.cnf" \
  -keyfile "$OUT/rsa-4096.key" -cert "$OUT/ca-root.pem" \
  -out "$OUT/empty.crl.pem" 2>/dev/null

rm -rf "$TMPCA"

# ---------------------------------------------------------------------------
# 23. Cert with only IP SANs (no DNS)
# ---------------------------------------------------------------------------
openssl req -new -x509 -key "$OUT/rsa-2048.key" -sha256 -days 365 \
  -subj "/CN=10.0.0.1" \
  -addext "subjectAltName=IP:10.0.0.1,IP:10.0.0.2,IP:172.16.0.1,IP:::1" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -out "$OUT/ip-only.pem" 2>/dev/null

# ---------------------------------------------------------------------------
# 24. Wildcard-only certificate
# ---------------------------------------------------------------------------
openssl req -new -x509 -key "$OUT/rsa-2048.key" -sha256 -days 365 \
  -subj "/C=US/O=Disco Inc/CN=*.wildcard.example.com" \
  -addext "subjectAltName=DNS:*.wildcard.example.com" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "extendedKeyUsage=serverAuth" \
  -out "$OUT/wildcard.pem" 2>/dev/null

# ---------------------------------------------------------------------------
# 25. Self-signed cert (not a CA, just self-signed leaf)
# ---------------------------------------------------------------------------
openssl req -new -x509 -key "$OUT/ec-secp384r1.key" -sha384 -days 365 \
  -subj "/CN=self-signed.local" \
  -addext "subjectAltName=DNS:self-signed.local" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "extendedKeyUsage=serverAuth" \
  -out "$OUT/self-signed.pem" 2>/dev/null

# ---------------------------------------------------------------------------
# 26. Cert with SHA-1 signature (legacy/weak)
# ---------------------------------------------------------------------------
openssl req -new -x509 -key "$OUT/rsa-2048.key" -sha1 -days 365 \
  -subj "/C=US/O=Legacy Corp/CN=sha1.legacy.example.com" \
  -addext "subjectAltName=DNS:sha1.legacy.example.com" \
  -out "$OUT/sha1-legacy.pem" 2>/dev/null

# ---------------------------------------------------------------------------
# 27. Cert with SHA-512 signature
# ---------------------------------------------------------------------------
openssl req -new -x509 -key "$OUT/rsa-4096.key" -sha512 -days 365 \
  -subj "/C=US/O=Disco Inc/CN=sha512.disco.example.com" \
  -addext "subjectAltName=DNS:sha512.disco.example.com" \
  -out "$OUT/sha512.pem" 2>/dev/null

# ---------------------------------------------------------------------------
# 28. Minimal / empty-ish subject cert (CN only)
# ---------------------------------------------------------------------------
openssl req -new -x509 -key "$OUT/rsa-2048.key" -sha256 -days 365 \
  -subj "/CN=minimal" \
  -out "$OUT/minimal.pem" 2>/dev/null

# ---------------------------------------------------------------------------
# 29. Cert with no CN (SAN-only, modern style)
# ---------------------------------------------------------------------------
openssl req -new -x509 -key "$OUT/ec-prime256v1.key" -sha256 -days 365 \
  -subj "/" \
  -addext "subjectAltName=DNS:no-cn.disco.example.com" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "extendedKeyUsage=serverAuth" \
  -out "$OUT/no-cn-san-only.pem" 2>/dev/null

# ---------------------------------------------------------------------------
# 30. Copy some files with alternate extensions for editor testing
# ---------------------------------------------------------------------------
cp "$OUT/server-rsa.crt" "$OUT/server.cert"
cp "$OUT/ca-root.pem" "$OUT/ca-root.cer"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "==> Generated test crypto files:"
echo ""
ls -1 "$OUT" | while read -r f; do
  printf "  %-40s %s\n" "$f" "$(wc -c < "$OUT/$f" | tr -d ' ') bytes"
done
echo ""
echo "==> Total: $(ls -1 "$OUT" | wc -l) files in $OUT"
