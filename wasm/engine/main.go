package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"syscall/js"
)

// CertInfo is the JSON-serializable representation of a parsed certificate.
type CertInfo struct {
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	SerialNumber       string   `json:"serialNumber"`
	NotBefore          string   `json:"notBefore"`
	NotAfter           string   `json:"notAfter"`
	SignatureAlgorithm string   `json:"signatureAlgorithm"`
	PublicKeyAlgorithm string   `json:"publicKeyAlgorithm"`
	PublicKeySize      int      `json:"publicKeySize"`
	IsCA               bool     `json:"isCA"`
	DNSNames           []string `json:"dnsNames"`
	EmailAddresses     []string `json:"emailAddresses"`
	IPAddresses        []string `json:"ipAddresses"`
	KeyUsages          []string `json:"keyUsages"`
	ExtKeyUsages       []string `json:"extKeyUsages"`
	Version            int      `json:"version"`
}

func getPublicKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

func keyUsageStrings(ku x509.KeyUsage) []string {
	var usages []string
	pairs := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Content Commitment"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Sign"},
		{x509.KeyUsageCRLSign, "CRL Sign"},
		{x509.KeyUsageEncipherOnly, "Encipher Only"},
		{x509.KeyUsageDecipherOnly, "Decipher Only"},
	}
	for _, p := range pairs {
		if ku&p.bit != 0 {
			usages = append(usages, p.name)
		}
	}
	return usages
}

func extKeyUsageStrings(ekus []x509.ExtKeyUsage) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                        "Any",
		x509.ExtKeyUsageServerAuth:                 "Server Authentication",
		x509.ExtKeyUsageClientAuth:                 "Client Authentication",
		x509.ExtKeyUsageCodeSigning:                "Code Signing",
		x509.ExtKeyUsageEmailProtection:            "Email Protection",
		x509.ExtKeyUsageTimeStamping:               "Time Stamping",
		x509.ExtKeyUsageOCSPSigning:                "OCSP Signing",
	}
	var result []string
	for _, eku := range ekus {
		if name, ok := names[eku]; ok {
			result = append(result, name)
		} else {
			result = append(result, fmt.Sprintf("Unknown (%d)", eku))
		}
	}
	return result
}

func certToInfo(cert *x509.Certificate) CertInfo {
	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}

	return CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore.UTC().Format("2006-01-02 15:04:05 UTC"),
		NotAfter:           cert.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC"),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeySize:      getPublicKeySize(cert),
		IsCA:               cert.IsCA,
		DNSNames:           cert.DNSNames,
		EmailAddresses:     cert.EmailAddresses,
		IPAddresses:        ips,
		KeyUsages:          keyUsageStrings(cert.KeyUsage),
		ExtKeyUsages:       extKeyUsageStrings(cert.ExtKeyUsage),
		Version:            cert.Version,
	}
}

// parsePEM accepts a PEM string from JS, parses all certificates in it,
// and returns a JSON string with the results.
func parsePEM(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return errorResult("expected PEM string argument")
	}

	pemStr := args[0].String()
	pemBytes := []byte(pemStr)

	var certs []CertInfo
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return errorResult(fmt.Sprintf("failed to parse certificate: %v", err))
			}
			certs = append(certs, certToInfo(cert))
		}

		pemBytes = rest
	}

	if len(certs) == 0 {
		return errorResult("no certificates found in PEM data")
	}

	result, err := json.Marshal(map[string]any{
		"ok":    true,
		"certs": certs,
	})
	if err != nil {
		return errorResult(fmt.Sprintf("failed to marshal JSON: %v", err))
	}

	return string(result)
}

func errorResult(msg string) string {
	result, _ := json.Marshal(map[string]any{
		"ok":    false,
		"error": msg,
	})
	return string(result)
}

func main() {
	// Expose functions to the JS global scope under a namespace
	js.Global().Set("DiscoEngine", js.ValueOf(map[string]any{
		"parsePEM": js.FuncOf(parsePEM),
	}))

	// Block forever — required for Go WASM to stay alive
	select {}
}
