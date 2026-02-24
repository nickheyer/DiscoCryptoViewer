//go:build js && wasm

package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"

	pb "github.com/nickheyer/discocryptoviewer/pkg/proto/discocrypto/v1"
	"google.golang.org/protobuf/proto"
	"software.sslmate.com/src/go-pkcs12"
)

// ---------------------------------------------------------------------------
// PKCS#7 / CMS  –  minimal ASN.1 structs for ContentInfo / SignedData
// ---------------------------------------------------------------------------

var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidDigestedData  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5}
	oidEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type cmsSignedData struct {
	Version      int
	DigestAlgos  asn1.RawValue
	ContentInfo  asn1.RawValue
	Certificates asn1.RawValue `asn1:"optional,tag:0"`
	CRLs         asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos  asn1.RawValue
}

type cmsSignerInfo struct {
	Version            int
	Sid                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// ---------------------------------------------------------------------------
// PKCS#7 / CMS
// ---------------------------------------------------------------------------

func handleParsePKCS7(input []byte) ([]byte, error) {
	req := &pb.ParsePKCS7Request{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	der := decodePEMOrRaw(req.Data, "PKCS7")

	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("pkcs7 contentInfo: %w", err)
	}

	p7 := &pb.PKCS7{Raw: req.Data}

	switch {
	case ci.ContentType.Equal(oidSignedData):
		p7.ContentType = pb.CMSContentType_CMS_CONTENT_TYPE_SIGNED_DATA
		var sd cmsSignedData
		if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
			return nil, fmt.Errorf("pkcs7 signedData: %w", err)
		}
		pbSD := &pb.CMSSignedData{Version: int32(sd.Version)}

		// Digest algorithms
		pbSD.DigestAlgorithms = parseAlgorithmSet(sd.DigestAlgos.Bytes)

		// Certificates
		if len(sd.Certificates.Bytes) > 0 {
			certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
			if err == nil {
				for _, c := range certs {
					pbSD.Certificates = append(pbSD.Certificates, convertCertificate(c))
				}
			}
		}

		// Signer infos
		pbSD.SignerInfos = parseSignerInfoSet(sd.SignerInfos.Bytes)

		p7.Content = &pb.PKCS7_SignedData{SignedData: pbSD}

	case ci.ContentType.Equal(oidEnvelopedData):
		p7.ContentType = pb.CMSContentType_CMS_CONTENT_TYPE_ENVELOPED_DATA
		p7.Content = &pb.PKCS7_RawData{RawData: ci.Content.Bytes}

	case ci.ContentType.Equal(oidEncryptedData):
		p7.ContentType = pb.CMSContentType_CMS_CONTENT_TYPE_ENCRYPTED_DATA
		p7.Content = &pb.PKCS7_RawData{RawData: ci.Content.Bytes}

	case ci.ContentType.Equal(oidDigestedData):
		p7.ContentType = pb.CMSContentType_CMS_CONTENT_TYPE_DIGESTED_DATA
		p7.Content = &pb.PKCS7_RawData{RawData: ci.Content.Bytes}

	case ci.ContentType.Equal(oidData):
		p7.ContentType = pb.CMSContentType_CMS_CONTENT_TYPE_DATA
		p7.Content = &pb.PKCS7_RawData{RawData: ci.Content.Bytes}

	default:
		p7.Content = &pb.PKCS7_RawData{RawData: ci.Content.Bytes}
	}

	resp := &pb.ParsePKCS7Response{
		Pkcs7:            p7,
		DetectedEncoding: detectEncoding(req.Data),
	}
	return proto.Marshal(resp)
}

// parseAlgorithmSet parses the inner bytes of a SET OF AlgorithmIdentifier.
func parseAlgorithmSet(raw []byte) []*pb.AlgorithmIdentifier {
	var out []*pb.AlgorithmIdentifier
	rest := raw
	for len(rest) > 0 {
		var aid pkix.AlgorithmIdentifier
		var err error
		rest, err = asn1.Unmarshal(rest, &aid)
		if err != nil {
			break
		}
		out = append(out, &pb.AlgorithmIdentifier{
			Algorithm:  convertOID(aid.Algorithm),
			Parameters: aid.Parameters.FullBytes,
		})
	}
	return out
}

// parseSignerInfoSet parses the inner bytes of a SET OF SignerInfo.
func parseSignerInfoSet(raw []byte) []*pb.CMSSignerInfo {
	var out []*pb.CMSSignerInfo
	rest := raw
	for len(rest) > 0 {
		// Grab each top-level SEQUENCE element
		var elem asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &elem)
		if err != nil {
			break
		}
		var si cmsSignerInfo
		if _, err := asn1.Unmarshal(elem.FullBytes, &si); err != nil {
			continue
		}
		pbSI := &pb.CMSSignerInfo{
			Version: int32(si.Version),
			DigestAlgorithm: &pb.AlgorithmIdentifier{
				Algorithm:  convertOID(si.DigestAlgorithm.Algorithm),
				Parameters: si.DigestAlgorithm.Parameters.FullBytes,
			},
			SignatureAlgorithm: &pb.AlgorithmIdentifier{
				Algorithm:  convertOID(si.SignatureAlgorithm.Algorithm),
				Parameters: si.SignatureAlgorithm.Parameters.FullBytes,
			},
			Signature: si.Signature,
		}

		// Parse SignerIdentifier — try IssuerAndSerialNumber
		var ias issuerAndSerial
		if _, err := asn1.Unmarshal(si.Sid.FullBytes, &ias); err == nil {
			var rdnSeq pkix.RDNSequence
			if _, err := asn1.Unmarshal(ias.Issuer.FullBytes, &rdnSeq); err == nil {
				var name pkix.Name
				name.FillFromRDNSequence(&rdnSeq)
				pbSI.Sid = &pb.CMSSignerIdentifier{
					Identifier: &pb.CMSSignerIdentifier_IssuerAndSerial{
						IssuerAndSerial: &pb.CMSIssuerAndSerialNumber{
							Issuer:       convertDN(name),
							SerialNumber: convertBigInt(ias.SerialNumber),
						},
					},
				}
			}
		}

		out = append(out, pbSI)
	}
	return out
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
