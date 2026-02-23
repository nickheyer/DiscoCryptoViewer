//go:build js && wasm

package main

import (
	"encoding/binary"
	"fmt"

	pb "github.com/nickheyer/discocryptoviewer/pkg/proto/discocrypto/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func handleParseSCT(input []byte) ([]byte, error) {
	req := &pb.ParseSCTRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	sct, err := parseSCTBytes(req.Data)
	if err != nil {
		return nil, err
	}

	resp := &pb.ParseSCTResponse{Sct: sct}
	return proto.Marshal(resp)
}

// parseSCTBytes parses a serialized SCT (RFC 6962 Section 3.2).
// Format: version (1) | log_id (32) | timestamp (8) | extensions_len (2) | extensions | hash_alg (1) | sig_alg (1) | sig_len (2) | sig
func parseSCTBytes(data []byte) (*pb.CTSignedCertificateTimestamp, error) {
	if len(data) < 44 { // minimum: 1+32+8+2+0+1+1+2+0
		return nil, fmt.Errorf("SCT too short: %d bytes", len(data))
	}

	offset := 0
	version := data[offset]
	offset++

	logID := data[offset : offset+32]
	offset += 32

	tsMillis := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	var extensions []byte
	if extLen > 0 {
		if offset+extLen > len(data) {
			return nil, fmt.Errorf("SCT extensions overflow")
		}
		extensions = data[offset : offset+extLen]
		offset += extLen
	}

	if offset+4 > len(data) {
		return nil, fmt.Errorf("SCT signature too short")
	}

	hashAlg := data[offset]
	offset++
	sigAlg := data[offset]
	offset++

	sigLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	var sig []byte
	if offset+sigLen <= len(data) {
		sig = data[offset : offset+sigLen]
	}

	ts := timestamppb.New(unixMillisToTime(int64(tsMillis)))

	return &pb.CTSignedCertificateTimestamp{
		Version:    pb.CTVersion(version + 1), // wire 0 → CT_VERSION_V1 (enum 1)
		LogId:      logID,
		Timestamp:  ts,
		Extensions: extensions,
		Signature: &pb.CTSignature{
			HashAlgorithm:      convertTLSHashAlg(hashAlg),
			SignatureAlgorithm: convertTLSSigAlg(sigAlg),
			Signature:          sig,
		},
	}, nil
}

func convertTLSHashAlg(v byte) pb.HashAlgorithm {
	switch v {
	case 4:
		return pb.HashAlgorithm_HASH_ALGORITHM_SHA256
	case 5:
		return pb.HashAlgorithm_HASH_ALGORITHM_SHA384
	case 6:
		return pb.HashAlgorithm_HASH_ALGORITHM_SHA512
	default:
		return pb.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED
	}
}

func convertTLSSigAlg(v byte) pb.SignatureAlgorithm {
	switch v {
	case 1:
		return pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_SHA256_WITH_RSA
	case 3:
		return pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA256
	default:
		return pb.SignatureAlgorithm_SIGNATURE_ALGORITHM_UNSPECIFIED
	}
}
