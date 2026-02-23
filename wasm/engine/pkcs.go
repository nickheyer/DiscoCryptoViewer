//go:build js && wasm

package main

import (
	"crypto/x509"
	"fmt"

	pb "github.com/nickheyer/discocryptoviewer/pkg/proto/discocrypto/v1"
	"google.golang.org/protobuf/proto"
	"software.sslmate.com/src/go-pkcs12"
)

// ---------------------------------------------------------------------------
// PKCS#7 / CMS
// ---------------------------------------------------------------------------

func handleParsePKCS7(input []byte) ([]byte, error) {
	req := &pb.ParsePKCS7Request{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	der := decodePEMOrRaw(req.Data, "PKCS7")

	// Basic PKCS#7 parsing: extract embedded certificates.
	// Full CMS parsing requires a dedicated library; we extract what the
	// Go stdlib can give us (certificate chains).
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		// Not directly parseable as certs; return raw structure
		resp := &pb.ParsePKCS7Response{
			Pkcs7:            &pb.PKCS7{Raw: req.Data},
			DetectedEncoding: detectEncoding(req.Data),
		}
		return proto.Marshal(resp)
	}

	var pbCerts []*pb.Certificate
	for _, c := range certs {
		pbCerts = append(pbCerts, convertCertificate(c))
	}

	resp := &pb.ParsePKCS7Response{
		Pkcs7: &pb.PKCS7{
			ContentType: pb.CMSContentType_CMS_CONTENT_TYPE_SIGNED_DATA,
			Content:     &pb.PKCS7_SignedData{SignedData: &pb.CMSSignedData{Certificates: pbCerts}},
			Raw:         req.Data,
		},
		DetectedEncoding: detectEncoding(req.Data),
	}
	return proto.Marshal(resp)
}

// ---------------------------------------------------------------------------
// PKCS#8
// ---------------------------------------------------------------------------

func handleParsePKCS8(input []byte) ([]byte, error) {
	req := &pb.ParsePKCS8Request{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	der := decodePEMOrRaw(req.Data, "PRIVATE KEY")

	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		// Might be encrypted PKCS#8
		resp := &pb.ParsePKCS8Response{
			Result:           &pb.ParsePKCS8Response_EncryptedPrivateKeyInfo{EncryptedPrivateKeyInfo: &pb.PKCS8EncryptedPrivateKeyInfo{EncryptedData: der}},
			DetectedEncoding: detectEncoding(req.Data),
		}
		return proto.Marshal(resp)
	}

	resp := &pb.ParsePKCS8Response{
		Result: &pb.ParsePKCS8Response_PrivateKeyInfo{
			PrivateKeyInfo: &pb.PKCS8PrivateKeyInfo{
				Version:   0,
				ParsedKey: convertPrivateKeyFull(key),
			},
		},
		DetectedEncoding: detectEncoding(req.Data),
	}
	return proto.Marshal(resp)
}

// ---------------------------------------------------------------------------
// PKCS#12 / PFX
// ---------------------------------------------------------------------------

func handleParsePKCS12(input []byte) ([]byte, error) {
	req := &pb.ParsePKCS12Request{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	privKey, cert, caCerts, err := pkcs12.DecodeChain(req.Data, req.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("decode PKCS#12: %w", err)
	}

	p12 := &pb.PKCS12{Version: 3}

	if cert != nil {
		p12.Certificates = append(p12.Certificates, convertCertificate(cert))
	}

	for _, ca := range caCerts {
		p12.Certificates = append(p12.Certificates, convertCertificate(ca))
	}
	if privKey != nil {
		p12.PrivateKey = convertPrivateKeyFull(privKey)
	}

	resp := &pb.ParsePKCS12Response{Pkcs12: p12}
	return proto.Marshal(resp)
}

// ---------------------------------------------------------------------------
// RFC 3161 Timestamp
// ---------------------------------------------------------------------------

func handleParseTimestamp(input []byte) ([]byte, error) {
	req := &pb.ParseTimestampRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	// RFC 3161 timestamp responses require ASN.1 parsing beyond stdlib.
	// Return raw data; full parsing can be added later.
	resp := &pb.ParseTimestampResponse{
		Timestamp:        &pb.TimestampResponse{Raw: req.Data},
		DetectedEncoding: detectEncoding(req.Data),
	}
	return proto.Marshal(resp)
}
