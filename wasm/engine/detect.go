//go:build js && wasm

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	pb "github.com/nickheyer/discocryptoviewer/pkg/proto/discocrypto/v1"
	"google.golang.org/protobuf/proto"
)

func handleDetect(input []byte) ([]byte, error) {
	req := &pb.DetectRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal DetectRequest: %w", err)
	}

	objects := detectObjects(req.Data, req.Filename)
	resp := &pb.DetectResponse{Objects: objects}
	return proto.Marshal(resp)
}

func detectObjects(data []byte, filename string) []*pb.DetectedObject {
	trimmed := bytes.TrimSpace(data)

	// PEM: may contain multiple blocks
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return detectPEMObjects(data)
	}

	// SSH public key (authorized_keys / .pub format)
	if isSSHPublicKeyFormat(trimmed) {
		return []*pb.DetectedObject{{
			Type:     pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_SSH_PUBLIC_KEY,
			Encoding: pb.Encoding_ENCODING_OPENSSH,
			Label:    "SSH Public Key",
		}}
	}

	// JSON: JWK, JWKS, or JWT-like
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return detectJSONObjects(trimmed)
	}

	// JWT compact serialization (three base64url segments)
	if isJWTCompact(trimmed) {
		return []*pb.DetectedObject{{
			Type:     pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_JWT,
			Encoding: pb.Encoding_ENCODING_JSON,
			Label:    "JSON Web Token",
		}}
	}

	// SRL: CA serial number file (hex string)
	if strings.HasSuffix(strings.ToLower(filename), ".srl") {
		return []*pb.DetectedObject{{
			Type:     pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PEM, // reuse PEM as generic text container
			Encoding: pb.Encoding_ENCODING_UNSPECIFIED,
			Label:    "CA Serial Number",
		}}
	}

	// DER / binary: try common ASN.1 structures
	if objs := detectDERObjects(data, filename); len(objs) > 0 {
		return objs
	}

	return nil
}

// ---------------------------------------------------------------------------
// PEM detection
// ---------------------------------------------------------------------------

var pemTypeMap = map[string]pb.CryptoObjectType{
	"CERTIFICATE":             pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_CERTIFICATE,
	"CERTIFICATE REQUEST":     pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_CERTIFICATE_REQUEST,
	"NEW CERTIFICATE REQUEST": pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_CERTIFICATE_REQUEST,
	"X509 CRL":                pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_CERTIFICATE_REVOCATION_LIST,
	"RSA PRIVATE KEY":         pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_RSA_PRIVATE_KEY,
	"RSA PUBLIC KEY":          pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_RSA_PUBLIC_KEY,
	"EC PRIVATE KEY":          pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_EC_PRIVATE_KEY,
	"EC PUBLIC KEY":           pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_EC_PUBLIC_KEY,
	"ENCRYPTED PRIVATE KEY":   pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PKCS8_ENCRYPTED_PRIVATE_KEY,
	"OPENSSH PRIVATE KEY":     pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_SSH_PRIVATE_KEY,
	"DSA PRIVATE KEY":         pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_DSA_PRIVATE_KEY,
	"DH PARAMETERS":           pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_DH_PARAMETERS,
	"PKCS7":                   pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PKCS7,
	"CMS":                     pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_CMS_SIGNED_DATA,
	"ATTRIBUTE CERTIFICATE":   pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_X509_ATTRIBUTE_CERTIFICATE,
	"PGP PUBLIC KEY BLOCK":    pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PGP_PUBLIC_KEY,
	"PGP PRIVATE KEY BLOCK":   pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PGP_PRIVATE_KEY,
	"PGP SIGNATURE":           pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PGP_SIGNATURE,
	"PGP MESSAGE":             pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PGP_SIGNATURE,
}

func detectPEMObjects(data []byte) []*pb.DetectedObject {
	var objects []*pb.DetectedObject
	rest := data
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}

		var objType pb.CryptoObjectType
		var label string

		switch block.Type {
		case "PUBLIC KEY":
			objType, label = classifySPKI(block.Bytes)
		case "PRIVATE KEY":
			objType, label = classifyPKCS8(block.Bytes)
		default:
			var ok bool
			objType, ok = pemTypeMap[block.Type]
			if !ok {
				objType = pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PEM
			}
			label = fmt.Sprintf("PEM: %s", block.Type)
		}

		objects = append(objects, &pb.DetectedObject{
			Type:     objType,
			Encoding: pb.Encoding_ENCODING_PEM,
			Label:    label,
		})
		rest = remainder
	}

	return objects
}

// classifySPKI parses a SPKI "PUBLIC KEY" DER blob to determine the actual algorithm.
func classifySPKI(der []byte) (pb.CryptoObjectType, string) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		// stdlib can't parse it — try OID detection for Ed448 etc.
		return classifySPKIByOID(der)
	}
	switch pub.(type) {
	case *rsa.PublicKey:
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_RSA_PUBLIC_KEY, "RSA Public Key"
	case *ecdsa.PublicKey:
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_EC_PUBLIC_KEY, "ECDSA Public Key"
	case ed25519.PublicKey:
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_ED25519_PUBLIC_KEY, "Ed25519 Public Key"
	case *ecdh.PublicKey:
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_ECDH_PUBLIC_KEY, "ECDH Public Key"
	default:
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_EC_PUBLIC_KEY, "Public Key"
	}
}

// classifySPKIByOID extracts the algorithm OID from a SPKI structure for keys
// the Go stdlib doesn't support (e.g. Ed448).
func classifySPKIByOID(der []byte) (pb.CryptoObjectType, string) {
	var spki struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PEM, "Public Key (unknown)"
	}
	oid := spki.Algorithm.Algorithm.String()
	switch oid {
	case "1.3.101.113": // Ed448
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_ED25519_PUBLIC_KEY, "Ed448 Public Key"
	case "1.3.101.110": // X25519
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_ECDH_PUBLIC_KEY, "X25519 Public Key"
	case "1.3.101.111": // X448
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_ECDH_PUBLIC_KEY, "X448 Public Key"
	default:
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PEM, fmt.Sprintf("Public Key (OID %s)", oid)
	}
}

// classifyPKCS8 parses a PKCS#8 "PRIVATE KEY" DER blob to determine the actual algorithm.
func classifyPKCS8(der []byte) (pb.CryptoObjectType, string) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return classifyPKCS8ByOID(der)
	}
	switch key.(type) {
	case *rsa.PrivateKey:
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_RSA_PRIVATE_KEY, "RSA Private Key"
	case *ecdsa.PrivateKey:
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_EC_PRIVATE_KEY, "ECDSA Private Key"
	case ed25519.PrivateKey:
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_ED25519_PRIVATE_KEY, "Ed25519 Private Key"
	case *ecdh.PrivateKey:
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_ECDH_PRIVATE_KEY, "ECDH Private Key"
	default:
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PKCS8_PRIVATE_KEY, "Private Key"
	}
}

// classifyPKCS8ByOID extracts the algorithm OID from a PKCS#8 structure for keys
// the Go stdlib doesn't support (e.g. Ed448).
func classifyPKCS8ByOID(der []byte) (pb.CryptoObjectType, string) {
	var pkcs8 struct {
		Version   int
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
		}
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(der, &pkcs8); err != nil {
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PKCS8_PRIVATE_KEY, "Private Key (unknown)"
	}
	oid := pkcs8.Algorithm.Algorithm.String()
	switch oid {
	case "1.3.101.113": // Ed448
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_ED25519_PRIVATE_KEY, "Ed448 Private Key"
	case "1.3.101.110": // X25519
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_ECDH_PRIVATE_KEY, "X25519 Private Key"
	case "1.3.101.111": // X448
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_ECDH_PRIVATE_KEY, "X448 Private Key"
	default:
		return pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PKCS8_PRIVATE_KEY, fmt.Sprintf("Private Key (OID %s)", oid)
	}
}

// ---------------------------------------------------------------------------
// SSH detection
// ---------------------------------------------------------------------------

func isSSHPublicKeyFormat(data []byte) bool {
	prefixes := []string{"ssh-rsa ", "ssh-ed25519 ", "ssh-dss ", "ecdsa-sha2-"}
	for _, p := range prefixes {
		if bytes.HasPrefix(data, []byte(p)) {
			return true
		}
	}
	// SSH certificate
	certPrefixes := []string{
		"ssh-rsa-cert-v01@openssh.com",
		"ssh-ed25519-cert-v01@openssh.com",
		"ssh-dss-cert-v01@openssh.com",
		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	}
	for _, p := range certPrefixes {
		if bytes.HasPrefix(data, []byte(p)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// JSON detection
// ---------------------------------------------------------------------------

func detectJSONObjects(data []byte) []*pb.DetectedObject {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil
	}
	if _, ok := obj["keys"]; ok {
		return []*pb.DetectedObject{{
			Type:     pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_JWKS,
			Encoding: pb.Encoding_ENCODING_JSON,
			Label:    "JSON Web Key Set",
		}}
	}
	if _, ok := obj["kty"]; ok {
		return []*pb.DetectedObject{{
			Type:     pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_JWK,
			Encoding: pb.Encoding_ENCODING_JSON,
			Label:    "JSON Web Key",
		}}
	}
	return nil
}

func isJWTCompact(data []byte) bool {
	s := string(data)
	parts := strings.Split(s, ".")
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0
}

// ---------------------------------------------------------------------------
// DER / binary detection
// ---------------------------------------------------------------------------

func detectDERObjects(data []byte, filename string) []*pb.DetectedObject {
	ext := strings.ToLower(filename)

	// PKCS#12 detection: starts with SEQUENCE containing an INTEGER (version)
	// and SEQUENCE with OID 1.2.840.113549.1.7.1 (pkcs7-data)
	if strings.HasSuffix(ext, ".p12") || strings.HasSuffix(ext, ".pfx") {
		return []*pb.DetectedObject{{
			Type:     pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PKCS12,
			Encoding: pb.Encoding_ENCODING_PKCS12,
			Label:    "PKCS#12 / PFX",
		}}
	}

	if len(data) < 2 {
		return nil
	}

	// ASN.1 SEQUENCE tag = 0x30
	if data[0] != 0x30 {
		return nil
	}

	// Heuristic: try parsing as known DER types by filename extension
	switch {
	case strings.HasSuffix(ext, ".cer") || strings.HasSuffix(ext, ".crt") || strings.HasSuffix(ext, ".der"):
		return []*pb.DetectedObject{{
			Type:     pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_CERTIFICATE,
			Encoding: pb.Encoding_ENCODING_DER,
			Label:    "DER Certificate",
		}}
	case strings.HasSuffix(ext, ".crl"):
		return []*pb.DetectedObject{{
			Type:     pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_CERTIFICATE_REVOCATION_LIST,
			Encoding: pb.Encoding_ENCODING_DER,
			Label:    "DER CRL",
		}}
	case strings.HasSuffix(ext, ".csr") || strings.HasSuffix(ext, ".req"):
		return []*pb.DetectedObject{{
			Type:     pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_CERTIFICATE_REQUEST,
			Encoding: pb.Encoding_ENCODING_DER,
			Label:    "DER CSR",
		}}
	case strings.HasSuffix(ext, ".key"):
		return []*pb.DetectedObject{{
			Type:     pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PKCS8_PRIVATE_KEY,
			Encoding: pb.Encoding_ENCODING_DER,
			Label:    "DER Private Key",
		}}
	case strings.HasSuffix(ext, ".p7b") || strings.HasSuffix(ext, ".p7c") || strings.HasSuffix(ext, ".p7s"):
		return []*pb.DetectedObject{{
			Type:     pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_PKCS7,
			Encoding: pb.Encoding_ENCODING_PKCS7,
			Label:    "PKCS#7",
		}}
	}

	// Fallback: try certificate parse
	return []*pb.DetectedObject{{
		Type:     pb.CryptoObjectType_CRYPTO_OBJECT_TYPE_CERTIFICATE,
		Encoding: pb.Encoding_ENCODING_DER,
		Label:    "DER Object",
	}}
}
