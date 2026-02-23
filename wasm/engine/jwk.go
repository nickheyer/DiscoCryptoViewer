//go:build js && wasm

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	pb "github.com/nickheyer/discocryptoviewer/pkg/proto/discocrypto/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func handleParseJWK(input []byte) ([]byte, error) {
	req := &pb.ParseJWKRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	jwk, err := parseJWKFromJSON(req.Data)
	if err != nil {
		return nil, err
	}

	resp := &pb.ParseJWKResponse{Jwk: jwk}
	return proto.Marshal(resp)
}

func handleParseJWKS(input []byte) ([]byte, error) {
	req := &pb.ParseJWKSRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(req.Data, &raw); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	var keys []*pb.JSONWebKey
	for _, k := range raw.Keys {
		jwk, err := parseJWKFromJSON(k)
		if err != nil {
			continue
		}
		keys = append(keys, jwk)
	}

	resp := &pb.ParseJWKSResponse{Jwks: &pb.JSONWebKeySet{Keys: keys}}
	return proto.Marshal(resp)
}

func handleParseJWT(input []byte) ([]byte, error) {
	req := &pb.ParseJWTRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	token := strings.TrimSpace(string(req.Data))
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode JWT header: %w", err)
	}

	payloadJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}

	sigBytes, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode JWT signature: %w", err)
	}

	header, err := parseJOSEHeader(headerJSON)
	if err != nil {
		return nil, fmt.Errorf("parse JWT header: %w", err)
	}

	claims, err := parseJWTClaims(payloadJSON)
	if err != nil {
		return nil, fmt.Errorf("parse JWT claims: %w", err)
	}

	resp := &pb.ParseJWTResponse{
		Jwt: &pb.JSONWebToken{
			Header:    header,
			Claims:    claims,
			Signature: sigBytes,
			Raw:       token,
		},
	}
	return proto.Marshal(resp)
}

func handleParseJWS(input []byte) ([]byte, error) {
	req := &pb.ParseJWSRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	token := strings.TrimSpace(string(req.Data))

	// Try compact serialization
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		payload, _ := base64URLDecode(parts[1])
		sig, _ := base64URLDecode(parts[2])
		headerJSON, _ := base64URLDecode(parts[0])
		header, _ := parseJOSEHeader(headerJSON)

		resp := &pb.ParseJWSResponse{
			Jws: &pb.JSONWebSignature{
				Payload:    payload,
				Signatures: []*pb.JWSSignature{{ProtectedHeader: header, Signature: sig}},
				Raw:        token,
			},
		}
		return proto.Marshal(resp)
	}

	return nil, fmt.Errorf("unsupported JWS format")
}

func handleParseJWE(input []byte) ([]byte, error) {
	req := &pb.ParseJWERequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	token := strings.TrimSpace(string(req.Data))
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid JWE: expected 5 parts, got %d", len(parts))
	}

	headerJSON, _ := base64URLDecode(parts[0])
	header, _ := parseJOSEHeader(headerJSON)
	encKey, _ := base64URLDecode(parts[1])
	iv, _ := base64URLDecode(parts[2])
	ciphertext, _ := base64URLDecode(parts[3])
	tag, _ := base64URLDecode(parts[4])

	resp := &pb.ParseJWEResponse{
		Jwe: &pb.JSONWebEncryption{
			Header:       header,
			EncryptedKey: encKey,
			Iv:           iv,
			Ciphertext:   ciphertext,
			Tag:          tag,
			Raw:          token,
		},
	}
	return proto.Marshal(resp)
}

// ---------------------------------------------------------------------------
// JSON parsers
// ---------------------------------------------------------------------------

type jwkJSON struct {
	Kty    string   `json:"kty"`
	Use    string   `json:"use"`
	KeyOps []string `json:"key_ops"`
	Alg    string   `json:"alg"`
	Kid    string   `json:"kid"`
	X5U    string   `json:"x5u"`
	X5T    string   `json:"x5t"`
	X5TS256 string  `json:"x5t#S256"`

	// RSA
	N string `json:"n"`
	E string `json:"e"`
	D string `json:"d"`
	P string `json:"p"`
	Q string `json:"q"`
	DP string `json:"dp"`
	DQ string `json:"dq"`
	QI string `json:"qi"`

	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`

	// Symmetric
	K string `json:"k"`
}

func parseJWKFromJSON(data []byte) (*pb.JSONWebKey, error) {
	var raw jwkJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse JWK JSON: %w", err)
	}

	jwk := &pb.JSONWebKey{
		Kty:    raw.Kty,
		Use:    raw.Use,
		KeyOps: raw.KeyOps,
		Alg:    raw.Alg,
		Kid:    raw.Kid,
		X5U:    raw.X5U,
	}

	if raw.X5T != "" {
		jwk.X5T, _ = base64URLDecode(raw.X5T)
	}
	if raw.X5TS256 != "" {
		jwk.X5TS256, _ = base64URLDecode(raw.X5TS256)
	}

	hasPrivate := raw.D != ""
	jwk.IsPrivate = hasPrivate

	switch strings.ToUpper(raw.Kty) {
	case "RSA":
		rsaData := &pb.JWKRSAKeyData{}
		rsaData.N, _ = base64URLDecode(raw.N)
		rsaData.E, _ = base64URLDecode(raw.E)
		if hasPrivate {
			rsaData.D, _ = base64URLDecode(raw.D)
			rsaData.P, _ = base64URLDecode(raw.P)
			rsaData.Q, _ = base64URLDecode(raw.Q)
			rsaData.Dp, _ = base64URLDecode(raw.DP)
			rsaData.Dq, _ = base64URLDecode(raw.DQ)
			rsaData.Qi, _ = base64URLDecode(raw.QI)
		}
		jwk.KeyData = &pb.JSONWebKey_Rsa{Rsa: rsaData}

	case "EC":
		ecData := &pb.JWKECKeyData{Crv: raw.Crv}
		ecData.X, _ = base64URLDecode(raw.X)
		ecData.Y, _ = base64URLDecode(raw.Y)
		if hasPrivate {
			ecData.D, _ = base64URLDecode(raw.D)
		}
		jwk.KeyData = &pb.JSONWebKey_Ec{Ec: ecData}

	case "OKP":
		okpData := &pb.JWKOctetKeyData{Crv: raw.Crv}
		okpData.X, _ = base64URLDecode(raw.X)
		if hasPrivate {
			okpData.D, _ = base64URLDecode(raw.D)
		}
		jwk.KeyData = &pb.JSONWebKey_Okp{Okp: okpData}

	case "OCT":
		symData := &pb.JWKSymmetricKeyData{}
		symData.K, _ = base64URLDecode(raw.K)
		jwk.KeyData = &pb.JSONWebKey_Oct{Oct: symData}
	}

	return jwk, nil
}

func parseJOSEHeader(data []byte) (*pb.JOSEHeader, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	header := &pb.JOSEHeader{Extra: make(map[string]string)}
	if v, ok := raw["alg"]; ok {
		json.Unmarshal(v, &header.Alg)
	}
	if v, ok := raw["typ"]; ok {
		json.Unmarshal(v, &header.Typ)
	}
	if v, ok := raw["cty"]; ok {
		json.Unmarshal(v, &header.Cty)
	}
	if v, ok := raw["kid"]; ok {
		json.Unmarshal(v, &header.Kid)
	}
	if v, ok := raw["enc"]; ok {
		json.Unmarshal(v, &header.Enc)
	}
	if v, ok := raw["zip"]; ok {
		json.Unmarshal(v, &header.Zip)
	}

	// Store remaining fields in Extra
	known := map[string]bool{"alg": true, "typ": true, "cty": true, "kid": true, "enc": true, "zip": true}
	for k, v := range raw {
		if !known[k] {
			header.Extra[k] = string(v)
		}
	}

	return header, nil
}

func parseJWTClaims(data []byte) (*pb.JWTClaims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	claims := &pb.JWTClaims{Extra: make(map[string]string)}

	if v, ok := raw["iss"]; ok {
		json.Unmarshal(v, &claims.Issuer)
	}
	if v, ok := raw["sub"]; ok {
		json.Unmarshal(v, &claims.Subject)
	}
	if v, ok := raw["aud"]; ok {
		// aud can be string or array
		var single string
		if err := json.Unmarshal(v, &single); err == nil {
			claims.Audience = []string{single}
		} else {
			json.Unmarshal(v, &claims.Audience)
		}
	}
	if v, ok := raw["jti"]; ok {
		json.Unmarshal(v, &claims.JwtId)
	}

	if v, ok := raw["exp"]; ok {
		claims.Expiration = parseNumericDate(v)
	}
	if v, ok := raw["nbf"]; ok {
		claims.NotBefore = parseNumericDate(v)
	}
	if v, ok := raw["iat"]; ok {
		claims.IssuedAt = parseNumericDate(v)
	}

	known := map[string]bool{"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true}
	for k, v := range raw {
		if !known[k] {
			claims.Extra[k] = string(v)
		}
	}

	return claims, nil
}

func parseNumericDate(data json.RawMessage) *timestamppb.Timestamp {
	var num float64
	if err := json.Unmarshal(data, &num); err != nil {
		return nil
	}
	sec := int64(num)
	nanos := int32((num - float64(sec)) * 1e9)
	return &timestamppb.Timestamp{Seconds: sec, Nanos: nanos}
}

// ---------------------------------------------------------------------------
// base64url helpers
// ---------------------------------------------------------------------------

func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}
