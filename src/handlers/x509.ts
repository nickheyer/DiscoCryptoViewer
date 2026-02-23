import { create } from '@bufbuild/protobuf';
import { callEngine } from '../wasmLoader';
import { CryptoObjectType } from '../proto/discocrypto/v1/common_pb';
import {
    ParseCertificateRequestSchema,
    ParseCertificateResponseSchema,
    ParseCSRRequestSchema,
    ParseCSRResponseSchema,
    ParseCRLRequestSchema,
    ParseCRLResponseSchema,
    ParseAttributeCertificateRequestSchema,
    ParseAttributeCertificateResponseSchema,
} from '../proto/discocrypto/v1/x509_pb';
import { ParsedObjectSchema, type ParsedObject } from '../proto/discocrypto/v1/parser_pb';
import type { CryptoHandler } from './index';

class X509Handler implements CryptoHandler {
    parse(data: Uint8Array, type: CryptoObjectType): ParsedObject[] {
        switch (type) {
            case CryptoObjectType.CERTIFICATE: {
                const req = create(ParseCertificateRequestSchema, { data });
                const res = callEngine('parseCertificate', req, ParseCertificateRequestSchema, ParseCertificateResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'X.509 Certificate',
                    object: { case: 'certificate', value: res.certificate! },
                })];
            }
            case CryptoObjectType.CERTIFICATE_REQUEST: {
                const req = create(ParseCSRRequestSchema, { data });
                const res = callEngine('parseCSR', req, ParseCSRRequestSchema, ParseCSRResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'Certificate Signing Request',
                    object: { case: 'certificateRequest', value: res.certificateRequest! },
                })];
            }
            case CryptoObjectType.CERTIFICATE_REVOCATION_LIST: {
                const req = create(ParseCRLRequestSchema, { data });
                const res = callEngine('parseCRL', req, ParseCRLRequestSchema, ParseCRLResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'Certificate Revocation List',
                    object: { case: 'crl', value: res.crl! },
                })];
            }
            case CryptoObjectType.X509_ATTRIBUTE_CERTIFICATE: {
                const req = create(ParseAttributeCertificateRequestSchema, { data });
                const res = callEngine('parseAttributeCertificate', req, ParseAttributeCertificateRequestSchema, ParseAttributeCertificateResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'Attribute Certificate',
                    object: { case: 'attributeCertificate', value: res.attributeCertificate! },
                })];
            }
            default:
                throw new Error(`X509Handler: unsupported type ${type}`);
        }
    }
}

export const x509Handler = new X509Handler();
