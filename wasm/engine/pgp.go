//go:build js && wasm

package main

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	pb "github.com/nickheyer/discocryptoviewer/pkg/proto/discocrypto/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func pgpBitLen(pk *packet.PublicKey) int32 {
	bl, err := pk.BitLength()
	if err != nil {
		return 0
	}
	return int32(bl)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func handleParsePGPPublicKey(input []byte) ([]byte, error) {
	req := &pb.ParsePGPPublicKeyRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	r := bytes.NewReader(req.Data)
	block, err := armor.Decode(r)
	if err != nil {
		// Try binary
		r.Reset(req.Data)
		el, err2 := openpgp.ReadKeyRing(r)
		if err2 != nil {
			return nil, fmt.Errorf("parse PGP public key: %w (armor: %v)", err2, err)
		}
		return marshalPGPPublicKeyResponse(el, req.Data)
	}

	el, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return nil, fmt.Errorf("parse PGP public key from armor: %w", err)
	}
	return marshalPGPPublicKeyResponse(el, req.Data)
}

func marshalPGPPublicKeyResponse(el openpgp.EntityList, raw []byte) ([]byte, error) {
	if len(el) == 0 {
		return nil, fmt.Errorf("no PGP entities found")
	}

	entity := el[0]
	resp := &pb.ParsePGPPublicKeyResponse{
		PublicKey:        convertPGPEntity(entity, raw),
		DetectedEncoding: detectEncoding(raw),
	}
	return proto.Marshal(resp)
}

func handleParsePGPPrivateKey(input []byte) ([]byte, error) {
	req := &pb.ParsePGPPrivateKeyRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	r := bytes.NewReader(req.Data)
	block, err := armor.Decode(r)
	if err != nil {
		r.Reset(req.Data)
		el, err2 := openpgp.ReadKeyRing(r)
		if err2 != nil {
			return nil, fmt.Errorf("parse PGP private key: %w", err2)
		}
		return marshalPGPPrivateKeyResponse(el, req)
	}

	el, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return nil, fmt.Errorf("parse PGP private key from armor: %w", err)
	}
	return marshalPGPPrivateKeyResponse(el, req)
}

func marshalPGPPrivateKeyResponse(el openpgp.EntityList, req *pb.ParsePGPPrivateKeyRequest) ([]byte, error) {
	if len(el) == 0 {
		return nil, fmt.Errorf("no PGP entities found")
	}

	entity := el[0]
	encrypted := entity.PrivateKey != nil && entity.PrivateKey.Encrypted

	if encrypted && req.Passphrase != "" {
		if err := entity.PrivateKey.Decrypt([]byte(req.Passphrase)); err != nil {
			return nil, fmt.Errorf("decrypt PGP private key: %w", err)
		}
	}

	resp := &pb.ParsePGPPrivateKeyResponse{
		PrivateKey: &pb.PGPPrivateKey{
			PublicKey: convertPGPEntity(entity, req.Data),
			Encrypted: encrypted,
		},
		DetectedEncoding: detectEncoding(req.Data),
	}
	return proto.Marshal(resp)
}

func handleParsePGPSignature(input []byte) ([]byte, error) {
	req := &pb.ParsePGPSignatureRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	r := bytes.NewReader(req.Data)
	block, err := armor.Decode(r)
	if err != nil {
		// Try binary packet
		r.Reset(req.Data)
	} else {
		r = bytes.NewReader(nil) // not used
		_ = block
	}

	// Parse signature packet from armor or binary
	var sigReader *bytes.Reader
	if block != nil {
		body, _ := io.ReadAll(block.Body)
		sigReader = bytes.NewReader(body)
	} else {
		sigReader = bytes.NewReader(req.Data)
	}
	pktReader := packet.NewReader(sigReader)
	p, err2 := pktReader.Next()
	if err2 != nil {
		return nil, fmt.Errorf("parse PGP signature: %w", err2)
	}

	sig, ok := p.(*packet.Signature)
	if !ok {
		return nil, fmt.Errorf("expected PGP signature packet, got %T", p)
	}

	resp := &pb.ParsePGPSignatureResponse{
		Signature: &pb.PGPSignature{
			Version:       int32(sig.Version),
			CreationTime:  timestamppb.New(sig.CreationTime),
			Raw:           req.Data,
		},
		DetectedEncoding: detectEncoding(req.Data),
	}
	return proto.Marshal(resp)
}

// ---------------------------------------------------------------------------
// Converters
// ---------------------------------------------------------------------------

func convertPGPEntity(entity *openpgp.Entity, raw []byte) *pb.PGPPublicKey {
	pk := entity.PrimaryKey

	pgpPub := &pb.PGPPublicKey{
		PrimaryKey: &pb.PGPKeyData{
			Version:      int32(pk.Version),
			CreationTime: timestamppb.New(pk.CreationTime),
			KeySizeBits:  pgpBitLen(pk),
			Fingerprint:  fmt.Sprintf("%X", pk.Fingerprint),
			KeyId:        fmt.Sprintf("%X", pk.KeyId),
			Algorithm:    convertPGPAlgorithm(pk.PubKeyAlgo),
		},
		KeyId:       fmt.Sprintf("%X", pk.KeyId),
		Fingerprint: fmt.Sprintf("%X", pk.Fingerprint),
		KeySizeBits: pgpBitLen(pk),
		Raw:         raw,
	}

	for uid := range entity.Identities {
		identity := entity.Identities[uid]
		pgpUID := &pb.PGPUserID{
			Id:    identity.Name,
			Name:  identity.UserId.Name,
			Email: identity.UserId.Email,
		}
		if identity.UserId.Comment != "" {
			pgpUID.Comment = identity.UserId.Comment
		}
		pgpPub.UserIds = append(pgpPub.UserIds, pgpUID)
	}

	for _, subkey := range entity.Subkeys {
		pgpPub.Subkeys = append(pgpPub.Subkeys, &pb.PGPSubkey{
			KeyData: &pb.PGPKeyData{
				Version:      int32(subkey.PublicKey.Version),
				CreationTime: timestamppb.New(subkey.PublicKey.CreationTime),
				KeySizeBits:  pgpBitLen(subkey.PublicKey),
				Fingerprint:  fmt.Sprintf("%X", subkey.PublicKey.Fingerprint),
				KeyId:        fmt.Sprintf("%X", subkey.PublicKey.KeyId),
				Algorithm:    convertPGPAlgorithm(subkey.PublicKey.PubKeyAlgo),
			},
		})
	}

	return pgpPub
}

func convertPGPAlgorithm(algo packet.PublicKeyAlgorithm) pb.PGPPublicKeyAlgorithm {
	switch algo {
	case packet.PubKeyAlgoRSA:
		return pb.PGPPublicKeyAlgorithm_PGP_PUBLIC_KEY_ALGORITHM_RSA
	case packet.PubKeyAlgoRSAEncryptOnly:
		return pb.PGPPublicKeyAlgorithm_PGP_PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_ONLY
	case packet.PubKeyAlgoRSASignOnly:
		return pb.PGPPublicKeyAlgorithm_PGP_PUBLIC_KEY_ALGORITHM_RSA_SIGN_ONLY
	case packet.PubKeyAlgoElGamal:
		return pb.PGPPublicKeyAlgorithm_PGP_PUBLIC_KEY_ALGORITHM_ELGAMAL
	case packet.PubKeyAlgoDSA:
		return pb.PGPPublicKeyAlgorithm_PGP_PUBLIC_KEY_ALGORITHM_DSA
	case packet.PubKeyAlgoECDH:
		return pb.PGPPublicKeyAlgorithm_PGP_PUBLIC_KEY_ALGORITHM_ECDH
	case packet.PubKeyAlgoECDSA:
		return pb.PGPPublicKeyAlgorithm_PGP_PUBLIC_KEY_ALGORITHM_ECDSA
	case packet.PubKeyAlgoEdDSA:
		return pb.PGPPublicKeyAlgorithm_PGP_PUBLIC_KEY_ALGORITHM_EDDSA
	default:
		return pb.PGPPublicKeyAlgorithm_PGP_PUBLIC_KEY_ALGORITHM_UNSPECIFIED
	}
}
