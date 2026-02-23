//go:build js && wasm

package main

import (
	"fmt"
	"time"

	pb "github.com/nickheyer/discocryptoviewer/pkg/proto/discocrypto/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func handleParseSSHPublicKey(input []byte) ([]byte, error) {
	req := &pb.ParseSSHPublicKeyRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	pub, comment, _, _, err := ssh.ParseAuthorizedKey(req.Data)
	if err != nil {
		// Try parsing as raw wire format
		pub, err = ssh.ParsePublicKey(req.Data)
		if err != nil {
			return nil, fmt.Errorf("parse SSH public key: %w", err)
		}
	}

	resp := &pb.ParseSSHPublicKeyResponse{
		PublicKey:        convertSSHPublicKey(pub, comment),
		DetectedEncoding: pb.Encoding_ENCODING_OPENSSH,
	}
	return proto.Marshal(resp)
}

func handleParseSSHPrivateKey(input []byte) ([]byte, error) {
	req := &pb.ParseSSHPrivateKeyRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	var rawKey any
	var err error
	if req.Passphrase != "" {
		rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase(req.Data, []byte(req.Passphrase))
	} else {
		rawKey, err = ssh.ParseRawPrivateKey(req.Data)
	}
	if err != nil {
		return nil, fmt.Errorf("parse SSH private key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(rawKey)
	if err != nil {
		return nil, fmt.Errorf("create signer from key: %w", err)
	}

	pubSSH := signer.PublicKey()

	resp := &pb.ParseSSHPrivateKeyResponse{
		PrivateKey: &pb.SSHPrivateKey{
			KeyType:    pubSSH.Type(),
			PrivateKey: convertPrivateKeyFull(rawKey),
			PublicKey:  convertSSHPublicKey(pubSSH, ""),
		},
	}
	return proto.Marshal(resp)
}

func handleParseSSHCertificate(input []byte) ([]byte, error) {
	req := &pb.ParseSSHCertificateRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(req.Data)
	if err != nil {
		return nil, fmt.Errorf("parse SSH certificate: %w", err)
	}

	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("parsed key is not an SSH certificate")
	}

	resp := &pb.ParseSSHCertificateResponse{
		Certificate: convertSSHCertificate(cert),
	}
	return proto.Marshal(resp)
}

// ---------------------------------------------------------------------------
// Converters
// ---------------------------------------------------------------------------

func convertSSHPublicKey(pub ssh.PublicKey, comment string) *pb.SSHPublicKey {
	fp := ssh.FingerprintSHA256(pub)
	fpMD5 := ssh.FingerprintLegacyMD5(pub)

	return &pb.SSHPublicKey{
		KeyType:           pub.Type(),
		Comment:           comment,
		FingerprintSha256: fp,
		FingerprintMd5:    fpMD5,
		Raw:               pub.Marshal(),
	}
}

func convertSSHCertificate(cert *ssh.Certificate) *pb.SSHCertificate {
	certType := pb.SSHCertType_SSH_CERT_TYPE_UNSPECIFIED
	switch cert.CertType {
	case ssh.UserCert:
		certType = pb.SSHCertType_SSH_CERT_TYPE_USER
	case ssh.HostCert:
		certType = pb.SSHCertType_SSH_CERT_TYPE_HOST
	}

	criticalOpts := make(map[string]string)
	for k, v := range cert.CriticalOptions {
		criticalOpts[k] = v
	}

	extensions := make(map[string]string)
	for k, v := range cert.Extensions {
		extensions[k] = v
	}

	pbCert := &pb.SSHCertificate{
		CertType:        certType,
		Serial:          cert.Serial,
		KeyId:           cert.KeyId,
		Key:             convertSSHPublicKey(cert.Key, ""),
		ValidPrincipals: cert.ValidPrincipals,
		CriticalOptions: criticalOpts,
		Extensions:      extensions,
		Nonce:           cert.Nonce,
		Signature:       cert.Signature.Blob,
		Raw:             cert.Marshal(),
	}

	if cert.ValidAfter != 0 {
		pbCert.ValidAfter = timestamppb.New(time.Unix(int64(cert.ValidAfter), 0))
	}
	if cert.ValidBefore != 0 && cert.ValidBefore != ^uint64(0) {
		pbCert.ValidBefore = timestamppb.New(time.Unix(int64(cert.ValidBefore), 0))
	}

	if cert.SignatureKey != nil {
		pbCert.SignatureKey = convertSSHPublicKey(cert.SignatureKey, "")
	}

	return pbCert
}
