//go:build js && wasm

package main

import (
	"crypto/dsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"

	pb "github.com/nickheyer/discocryptoviewer/pkg/proto/discocrypto/v1"
	"google.golang.org/protobuf/proto"
)

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func handleParsePublicKey(input []byte) ([]byte, error) {
	req := &pb.ParsePublicKeyRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	pub, err := parseAnyPublicKey(req.Data)
	if err != nil {
		return nil, err
	}

	resp := &pb.ParsePublicKeyResponse{
		PublicKey:        convertPublicKeyFull(pub),
		DetectedEncoding: detectEncoding(req.Data),
	}
	return proto.Marshal(resp)
}

func handleParsePrivateKey(input []byte) ([]byte, error) {
	req := &pb.ParsePrivateKeyRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	priv, err := parseAnyPrivateKey(req.Data)
	if err != nil {
		return nil, err
	}

	resp := &pb.ParsePrivateKeyResponse{
		PrivateKey:       convertPrivateKeyFull(priv),
		DetectedEncoding: detectEncoding(req.Data),
	}
	return proto.Marshal(resp)
}

func handleParseDHParameters(input []byte) ([]byte, error) {
	req := &pb.ParseDHParametersRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	der := decodePEMOrRaw(req.Data, "DH PARAMETERS")
	params, err := parseDHParams(der)
	if err != nil {
		return nil, err
	}

	resp := &pb.ParseDHParametersResponse{
		Parameters:       params,
		DetectedEncoding: detectEncoding(req.Data),
	}
	return proto.Marshal(resp)
}

// ---------------------------------------------------------------------------
// Public key parsing (tries all formats)
// ---------------------------------------------------------------------------

func parseAnyPublicKey(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	der := data
	if block != nil {
		der = block.Bytes
		switch block.Type {
		case "RSA PUBLIC KEY":
			return x509.ParsePKCS1PublicKey(der)
		case "PUBLIC KEY", "EC PUBLIC KEY":
			pub, err := x509.ParsePKIXPublicKey(der)
			if err == nil {
				return pub, nil
			}
			// stdlib failed — try raw SPKI extraction (Ed448 etc.)
			return parseSPKIRaw(der)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err == nil {
			return pub, nil
		}
		return parseSPKIRaw(der)
	}

	// Try PKIX (SPKI) format
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		return pub, nil
	}
	// Try PKCS#1 RSA
	if pub, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return pub, nil
	}
	// Try raw SPKI for unsupported algorithms
	if pub, err := parseSPKIRaw(der); err == nil {
		return pub, nil
	}

	return nil, fmt.Errorf("unable to parse public key in any known format")
}

// rawSPKIKey represents a public key parsed from raw SPKI ASN.1 when Go stdlib
// doesn't support the algorithm (e.g. Ed448).
type rawSPKIKey struct {
	Algorithm string
	KeyData   []byte
}

func parseSPKIRaw(der []byte) (*rawSPKIKey, error) {
	var spki struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("unable to parse SPKI: %w", err)
	}
	oid := spki.Algorithm.Algorithm.String()
	name := oid
	switch oid {
	case "1.3.101.112":
		name = "Ed25519"
	case "1.3.101.113":
		name = "Ed448"
	case "1.3.101.110":
		name = "X25519"
	case "1.3.101.111":
		name = "X448"
	}
	return &rawSPKIKey{Algorithm: name, KeyData: spki.PublicKey.Bytes}, nil
}

// ---------------------------------------------------------------------------
// Private key parsing (tries all formats)
// ---------------------------------------------------------------------------

func parseAnyPrivateKey(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		switch block.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				return key, nil
			}
			// stdlib failed — try raw PKCS#8 extraction (Ed448 etc.)
			return parsePKCS8Raw(block.Bytes)
		case "ENCRYPTED PRIVATE KEY":
			return nil, fmt.Errorf("encrypted PKCS#8 key requires passphrase (use parsePKCS8)")
		case "DSA PRIVATE KEY":
			return parseDSAPrivateKey(block.Bytes)
		}
		// Fallback: try all formats
		return tryAllPrivateKeyFormats(block.Bytes)
	}

	return tryAllPrivateKeyFormats(data)
}

func tryAllPrivateKeyFormats(der []byte) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := parseDSAPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unable to parse private key in any known format")
}

// ---------------------------------------------------------------------------
// DSA private key (ASN.1 OpenSSL format)
// ---------------------------------------------------------------------------

func parseDSAPrivateKey(der []byte) (*dsa.PrivateKey, error) {
	// OpenSSL DSA private key format:
	// SEQUENCE { version INTEGER, p INTEGER, q INTEGER, g INTEGER, y INTEGER, x INTEGER }
	var raw struct {
		Version int
		P       *big.Int
		Q       *big.Int
		G       *big.Int
		Y       *big.Int
		X       *big.Int
	}
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, fmt.Errorf("parse DSA private key: %w", err)
	}
	return &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{P: raw.P, Q: raw.Q, G: raw.G},
			Y:          raw.Y,
		},
		X: raw.X,
	}, nil
}

// DSA public key conversion (dsa.PublicKey is not in convert.go since it's
// handled through the generic convertPublicKey; we extend it here).

func init() {
	// Extend convertPublicKey to handle DSA via a wrapper called from keys handler.
}

func convertDSAPublicKey(k *dsa.PublicKey) *pb.PublicKey {
	return &pb.PublicKey{
		Algorithm: pb.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_DSA,
		Key: &pb.PublicKey_Dsa{Dsa: &pb.DSAPublicKey{
			Parameters: &pb.DSAParameters{
				P: convertBigInt(k.Parameters.P),
				Q: convertBigInt(k.Parameters.Q),
				G: convertBigInt(k.Parameters.G),
			},
			Y:           convertBigInt(k.Y),
			KeySizeBits: int32(k.P.BitLen()),
		}},
	}
}

func convertDSAPrivateKey(k *dsa.PrivateKey) *pb.PrivateKey {
	return &pb.PrivateKey{
		Algorithm: pb.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_DSA,
		Key: &pb.PrivateKey_Dsa{Dsa: &pb.DSAPrivateKey{
			PublicKey: convertDSAPublicKey(&k.PublicKey).GetDsa(),
			X:         convertBigInt(k.X),
		}},
	}
}

func convertPublicKeyFull(pub any) *pb.PublicKey {
	switch k := pub.(type) {
	case *dsa.PublicKey:
		return convertDSAPublicKey(k)
	case *rawSPKIKey:
		pk := &pb.PublicKey{}
		switch k.Algorithm {
		case "Ed448":
			pk.Algorithm = pb.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_ED25519
			pk.Key = &pb.PublicKey_Ed25519{Ed25519: &pb.Ed25519PublicKey{
				KeyData: k.KeyData,
			}}
		default:
			pk.Key = &pb.PublicKey_Ecdh{Ecdh: &pb.ECDHPublicKey{
				KeyData: k.KeyData,
			}}
		}
		return pk
	default:
		_ = k
		return convertPublicKey(pub)
	}
}

// rawPKCS8Key represents a private key parsed from raw PKCS#8 ASN.1 when Go
// stdlib doesn't support the algorithm (e.g. Ed448).
type rawPKCS8Key struct {
	Algorithm string
	KeyData   []byte
}

func parsePKCS8Raw(der []byte) (*rawPKCS8Key, error) {
	var pkcs8 struct {
		Version   int
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
		}
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(der, &pkcs8); err != nil {
		return nil, fmt.Errorf("unable to parse PKCS#8: %w", err)
	}
	oid := pkcs8.Algorithm.Algorithm.String()
	name := oid
	switch oid {
	case "1.3.101.112":
		name = "Ed25519"
	case "1.3.101.113":
		name = "Ed448"
	case "1.3.101.110":
		name = "X25519"
	case "1.3.101.111":
		name = "X448"
	}
	return &rawPKCS8Key{Algorithm: name, KeyData: pkcs8.PrivateKey}, nil
}

func convertPrivateKeyFull(priv any) *pb.PrivateKey {
	switch k := priv.(type) {
	case *dsa.PrivateKey:
		return convertDSAPrivateKey(k)
	case *rawPKCS8Key:
		pk := &pb.PrivateKey{}
		switch k.Algorithm {
		case "Ed448":
			pk.Algorithm = pb.PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_ED25519
			pk.Key = &pb.PrivateKey_Ed25519{Ed25519: &pb.Ed25519PrivateKey{
				Seed: k.KeyData,
			}}
		default:
			pk.Key = &pb.PrivateKey_Ecdh{Ecdh: &pb.ECDHPrivateKey{
				KeyData: k.KeyData,
			}}
		}
		return pk
	default:
		_ = k
		return convertPrivateKey(priv)
	}
}

// ---------------------------------------------------------------------------
// DH parameters parsing (ASN.1)
// ---------------------------------------------------------------------------

func parseDHParams(der []byte) (*pb.DHParameters, error) {
	var params struct {
		P *big.Int
		G *big.Int
	}
	if _, err := asn1.Unmarshal(der, &params); err != nil {
		return nil, fmt.Errorf("parse DH parameters: %w", err)
	}
	return &pb.DHParameters{
		P:           convertBigInt(params.P),
		G:           convertBigInt(params.G),
		KeySizeBits: int32(params.P.BitLen()),
	}, nil
}
