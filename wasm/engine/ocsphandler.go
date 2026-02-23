//go:build js && wasm

package main

import (
	"fmt"

	pb "github.com/nickheyer/discocryptoviewer/pkg/proto/discocrypto/v1"
	"golang.org/x/crypto/ocsp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func handleParseOCSPRequest(input []byte) ([]byte, error) {
	req := &pb.ParseOCSPRequestRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	ocspReq, err := ocsp.ParseRequest(req.Data)
	if err != nil {
		return nil, fmt.Errorf("parse OCSP request: %w", err)
	}

	resp := &pb.ParseOCSPRequestResponse{
		Request: &pb.OCSPRequest{
			IssuerNameHash: ocspReq.IssuerNameHash,
			IssuerKeyHash:  ocspReq.IssuerKeyHash,
			SerialNumber:   convertBigInt(ocspReq.SerialNumber),
			Raw:            req.Data,
		},
		DetectedEncoding: pb.Encoding_ENCODING_DER,
	}
	return proto.Marshal(resp)
}

func handleParseOCSPResponse(input []byte) ([]byte, error) {
	req := &pb.ParseOCSPResponseRequest{}
	if err := proto.Unmarshal(input, req); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	ocspResp, err := ocsp.ParseResponse(req.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("parse OCSP response: %w", err)
	}

	certStatus := pb.OCSPCertStatus_OCSP_CERT_STATUS_GOOD
	switch ocspResp.Status {
	case ocsp.Revoked:
		certStatus = pb.OCSPCertStatus_OCSP_CERT_STATUS_REVOKED
	case ocsp.Unknown:
		certStatus = pb.OCSPCertStatus_OCSP_CERT_STATUS_UNKNOWN
	}

	singleResp := &pb.OCSPSingleResponse{
		SerialNumber: convertBigInt(ocspResp.SerialNumber),
		CertStatus:   certStatus,
		ThisUpdate:   timestamppb.New(ocspResp.ThisUpdate),
		NextUpdate:   timestamppb.New(ocspResp.NextUpdate),
	}

	if ocspResp.Status == ocsp.Revoked {
		singleResp.RevocationTime = timestamppb.New(ocspResp.RevokedAt)
		singleResp.RevocationReason = pb.RevocationReason(ocspResp.RevocationReason)
	}

	basicResp := &pb.OCSPBasicResponse{
		Responses:          []*pb.OCSPSingleResponse{singleResp},
		ProducedAt:         timestamppb.New(ocspResp.ProducedAt),
		SignatureAlgorithm: convertSignatureAlgorithm(ocspResp.SignatureAlgorithm),
		Signature:          ocspResp.Signature,
	}

	if len(ocspResp.RawResponderName) > 0 {
		basicResp.ResponderId = &pb.OCSPBasicResponse_ResponderKeyHash{
			ResponderKeyHash: ocspResp.ResponderKeyHash,
		}
	}

	resp := &pb.ParseOCSPResponseResponse{
		Response: &pb.OCSPResponse{
			Status:   pb.OCSPResponseStatus_OCSP_RESPONSE_STATUS_SUCCESSFUL,
			Response: basicResp,
			Raw:      req.Data,
		},
		DetectedEncoding: pb.Encoding_ENCODING_DER,
	}
	return proto.Marshal(resp)
}
