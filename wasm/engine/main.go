//go:build js && wasm

package main

import (
	"syscall/js" // requires GOOS=js GOARCH=wasm; see //go:build constraint above
	"time"
)

func unixMillisToTime(ms int64) time.Time {
	return time.Unix(ms/1000, (ms%1000)*int64(time.Millisecond))
}

func main() {
	engine := map[string]any{
		// Parser service
		"detect": wrapHandler(handleDetect),

		// X.509 service
		"parseCertificate":          wrapHandler(handleParseCertificate),
		"parseCSR":                  wrapHandler(handleParseCSR),
		"parseCRL":                  wrapHandler(handleParseCRL),
		"parseAttributeCertificate": wrapHandler(handleParseAttributeCertificate),

		// Key service
		"parsePublicKey":    wrapHandler(handleParsePublicKey),
		"parsePrivateKey":   wrapHandler(handleParsePrivateKey),
		"parseDHParameters": wrapHandler(handleParseDHParameters),

		// PEM service
		"decodePem": wrapHandler(handleDecodePem),

		// PKCS service
		"parsePKCS7":     wrapHandler(handleParsePKCS7),
		"parsePKCS8":     wrapHandler(handleParsePKCS8),
		"parsePKCS12":    wrapHandler(handleParsePKCS12),
		"parseTimestamp": wrapHandler(handleParseTimestamp),

		// SSH service
		"parseSSHPublicKey":   wrapHandler(handleParseSSHPublicKey),
		"parseSSHPrivateKey":  wrapHandler(handleParseSSHPrivateKey),
		"parseSSHCertificate": wrapHandler(handleParseSSHCertificate),

		// PGP service
		"parsePGPPublicKey":  wrapHandler(handleParsePGPPublicKey),
		"parsePGPPrivateKey": wrapHandler(handleParsePGPPrivateKey),
		"parsePGPSignature":  wrapHandler(handleParsePGPSignature),

		// JWK service
		"parseJWK":  wrapHandler(handleParseJWK),
		"parseJWKS": wrapHandler(handleParseJWKS),
		"parseJWT":  wrapHandler(handleParseJWT),
		"parseJWS":  wrapHandler(handleParseJWS),
		"parseJWE":  wrapHandler(handleParseJWE),

		// OCSP service
		"parseOCSPRequest":  wrapHandler(handleParseOCSPRequest),
		"parseOCSPResponse": wrapHandler(handleParseOCSPResponse),

		// CT service
		"parseSCT": wrapHandler(handleParseSCT),
	}

	js.Global().Set("DiscoEngine", js.ValueOf(engine))

	// Block forever — the Go runtime must stay alive for the JS callbacks.
	select {}
}
