//go:build js && wasm

package main

import (
	"encoding/pem"
	"fmt"

	pb "github.com/nickheyer/discocryptoviewer/pkg/proto/discocrypto/v1"
	"google.golang.org/protobuf/proto"
)

func handleDecodePem(input []byte) ([]byte, error) {
	req := &pb.DecodePemRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	var blocks []*pb.PemBlock
	rest := req.Data
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		blocks = append(blocks, convertPemBlock(block))
		rest = remainder
	}

	if len(blocks) == 0 {
		blocks = append(blocks, &pb.PemBlock{
			Type: "DATA",
			Data: req.Data,
		})
	}

	resp := &pb.DecodePemResponse{
		PemFile: &pb.PemFile{Blocks: blocks},
	}
	return proto.Marshal(resp)
}

var pemTypeEnumMap = map[string]pb.PemType{
	"CERTIFICATE":             pb.PemType_PEM_TYPE_CERTIFICATE,
	"CERTIFICATE REQUEST":     pb.PemType_PEM_TYPE_CERTIFICATE_REQUEST,
	"NEW CERTIFICATE REQUEST": pb.PemType_PEM_TYPE_CERTIFICATE_REQUEST,
	"X509 CRL":                pb.PemType_PEM_TYPE_X509_CRL,
	"RSA PRIVATE KEY":         pb.PemType_PEM_TYPE_RSA_PRIVATE_KEY,
	"RSA PUBLIC KEY":          pb.PemType_PEM_TYPE_RSA_PUBLIC_KEY,
	"EC PRIVATE KEY":          pb.PemType_PEM_TYPE_EC_PRIVATE_KEY,
	"EC PUBLIC KEY":           pb.PemType_PEM_TYPE_EC_PUBLIC_KEY,
	"PRIVATE KEY":             pb.PemType_PEM_TYPE_PRIVATE_KEY,
	"PUBLIC KEY":              pb.PemType_PEM_TYPE_PUBLIC_KEY,
	"ENCRYPTED PRIVATE KEY":   pb.PemType_PEM_TYPE_ENCRYPTED_PRIVATE_KEY,
	"OPENSSH PRIVATE KEY":     pb.PemType_PEM_TYPE_OPENSSH_PRIVATE_KEY,
	"DSA PRIVATE KEY":         pb.PemType_PEM_TYPE_DSA_PRIVATE_KEY,
	"DSA PUBLIC KEY":          pb.PemType_PEM_TYPE_DSA_PUBLIC_KEY,
	"DH PARAMETERS":           pb.PemType_PEM_TYPE_DH_PARAMETERS,
	"PKCS7":                   pb.PemType_PEM_TYPE_PKCS7,
	"CMS":                     pb.PemType_PEM_TYPE_CMS,
	"ATTRIBUTE CERTIFICATE":   pb.PemType_PEM_TYPE_ATTRIBUTE_CERTIFICATE,
}

func convertPemBlock(block *pem.Block) *pb.PemBlock {
	pemType := pb.PemType_PEM_TYPE_UNSPECIFIED
	if pt, ok := pemTypeEnumMap[block.Type]; ok {
		pemType = pt
	}

	headers := make(map[string]string)
	for k, v := range block.Headers {
		headers[k] = v
	}

	return &pb.PemBlock{
		Type:    block.Type,
		PemType: pemType,
		Headers: headers,
		Data:    block.Bytes,
	}
}
