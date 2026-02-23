//go:build js && wasm

package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	pb "github.com/nickheyer/discocryptoviewer/pkg/proto/discocrypto/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func handleParseCertificate(input []byte) ([]byte, error) {
	req := &pb.ParseCertificateRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	der := decodePEMOrRaw(req.Data, "CERTIFICATE")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	resp := &pb.ParseCertificateResponse{
		Certificate:      convertCertificate(cert),
		DetectedEncoding: detectEncoding(req.Data),
	}
	return proto.Marshal(resp)
}

func handleParseCSR(input []byte) ([]byte, error) {
	req := &pb.ParseCSRRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	der := decodePEMOrRaw(req.Data, "CERTIFICATE REQUEST")
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}

	resp := &pb.ParseCSRResponse{
		CertificateRequest: convertCSR(csr),
		DetectedEncoding:   detectEncoding(req.Data),
	}
	return proto.Marshal(resp)
}

func handleParseCRL(input []byte) ([]byte, error) {
	req := &pb.ParseCRLRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	der := decodePEMOrRaw(req.Data, "X509 CRL")
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("parse CRL: %w", err)
	}

	resp := &pb.ParseCRLResponse{
		Crl:              convertCRL(crl),
		DetectedEncoding: detectEncoding(req.Data),
	}
	return proto.Marshal(resp)
}

func handleParseAttributeCertificate(input []byte) ([]byte, error) {
	req := &pb.ParseAttributeCertificateRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	// Attribute certificates (RFC 5755) are not natively supported by Go stdlib.
	// Return the raw DER for now; full parsing can be added with ASN.1.
	resp := &pb.ParseAttributeCertificateResponse{
		AttributeCertificate: &pb.AttributeCertificate{Raw: req.Data},
		DetectedEncoding:     detectEncoding(req.Data),
	}
	return proto.Marshal(resp)
}

// ---------------------------------------------------------------------------
// PEM-or-raw helper
// ---------------------------------------------------------------------------

func decodePEMOrRaw(data []byte, _ string) []byte {
	block, _ := pem.Decode(data)
	if block != nil {
		return block.Bytes
	}
	return data
}

// ---------------------------------------------------------------------------
// Certificate conversion
// ---------------------------------------------------------------------------

func convertCertificate(cert *x509.Certificate) *pb.Certificate {
	c := &pb.Certificate{
		Version:            int32(cert.Version),
		SerialNumber:       convertBigInt(cert.SerialNumber),
		SignatureAlgorithm: convertSignatureAlgorithm(cert.SignatureAlgorithm),
		Issuer:             convertDN(cert.Issuer),
		Subject:            convertDN(cert.Subject),
		Validity:           convertValidity(cert.NotBefore, cert.NotAfter),
		PublicKeyAlgorithm: convertPublicKeyAlgorithm(cert.PublicKeyAlgorithm),
		PublicKeyInfo:      convertSPKI(cert.RawSubjectPublicKeyInfo),
		Signature:          cert.Signature,
		Fingerprints:       computeFingerprints(cert.Raw),
		BasicConstraints: &pb.BasicConstraints{
			IsCa:           cert.IsCA,
			MaxPathLen:     int32(cert.MaxPathLen),
			MaxPathLenZero: cert.MaxPathLenZero,
		},
		KeyUsage:                    convertKeyUsages(cert.KeyUsage),
		ExtKeyUsage:                 convertExtKeyUsages(cert.ExtKeyUsage),
		UnknownExtKeyUsage:          convertOIDs(cert.UnknownExtKeyUsage),
		SubjectAltNames:             convertSANs(cert),
		SubjectKeyId:                cert.SubjectKeyId,
		AuthorityKeyId:              &pb.AuthorityKeyIdentifier{KeyId: cert.AuthorityKeyId},
		CrlDistributionPoints:       convertCRLDistPoints(cert.CRLDistributionPoints),
		AuthorityInfoAccess:         &pb.AuthorityInfoAccess{OcspServers: cert.OCSPServer, IssuingCertificateUrls: cert.IssuingCertificateURL},
		NameConstraints:             convertNameConstraints(cert),
		Extensions:                  convertExtensions(cert.Extensions),
		UnhandledCriticalExtensions: convertOIDs(cert.UnhandledCriticalExtensions),
		Raw:                         cert.Raw,
		RawTbsCertificate:           cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo:     cert.RawSubjectPublicKeyInfo,
		RawSubject:                  cert.RawSubject,
		RawIssuer:                   cert.RawIssuer,
		IsSelfSigned:                isSelfSigned(cert),
	}

	for _, oid := range cert.PolicyIdentifiers {
		c.PolicyIdentifiers = append(c.PolicyIdentifiers, convertOID(oid))
	}

	return c
}

// ---------------------------------------------------------------------------
// CSR conversion
// ---------------------------------------------------------------------------

func convertCSR(csr *x509.CertificateRequest) *pb.CertificateRequest {
	cr := &pb.CertificateRequest{
		Version:            int32(csr.Version),
		Subject:            convertDN(csr.Subject),
		SignatureAlgorithm: convertSignatureAlgorithm(csr.SignatureAlgorithm),
		PublicKeyAlgorithm: convertPublicKeyAlgorithm(csr.PublicKeyAlgorithm),
		PublicKeyInfo:      convertSPKI(csr.RawSubjectPublicKeyInfo),
		Signature:          csr.Signature,
		SubjectAltNames: &pb.SubjectAlternativeNames{
			DnsNames:       csr.DNSNames,
			EmailAddresses: csr.EmailAddresses,
		},
		Extensions:             convertExtensions(csr.Extensions),
		ExtraExtensions:        convertExtensions(csr.ExtraExtensions),
		Fingerprints:           computeFingerprints(csr.Raw),
		Raw:                    csr.Raw,
		RawTbsCertificateRequest: csr.RawTBSCertificateRequest,
		RawSubjectPublicKeyInfo:  csr.RawSubjectPublicKeyInfo,
		RawSubject:               csr.RawSubject,
	}
	for _, ip := range csr.IPAddresses {
		cr.SubjectAltNames.IpAddresses = append(cr.SubjectAltNames.IpAddresses, ip)
	}
	for _, u := range csr.URIs {
		cr.SubjectAltNames.Uris = append(cr.SubjectAltNames.Uris, u.String())
	}
	return cr
}

// ---------------------------------------------------------------------------
// CRL conversion
// ---------------------------------------------------------------------------

func convertCRL(crl *x509.RevocationList) *pb.CertificateRevocationList {
	c := &pb.CertificateRevocationList{
		Issuer:             convertDN(crl.Issuer),
		SignatureAlgorithm: convertSignatureAlgorithm(crl.SignatureAlgorithm),
		Signature:          crl.Signature,
		ThisUpdate:         timestamppb.New(crl.ThisUpdate),
		NextUpdate:         timestamppb.New(crl.NextUpdate),
		Extensions:         convertExtensions(crl.Extensions),
		AuthorityKeyId:     crl.AuthorityKeyId,
		Number:             convertBigInt(crl.Number),
		Fingerprints:       computeFingerprints(crl.Raw),
		Raw:                crl.Raw,
		RawTbsRevocationList: crl.RawTBSRevocationList,
		RawIssuer:            crl.RawIssuer,
	}

	for _, rc := range crl.RevokedCertificateEntries {
		c.RevokedCertificates = append(c.RevokedCertificates, &pb.RevokedCertificate{
			SerialNumber:   convertBigInt(rc.SerialNumber),
			RevocationTime: timestamppb.New(rc.RevocationTime),
			Extensions:     convertExtensions(rc.Extensions),
		})
	}

	return c
}
