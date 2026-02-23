import { create } from '@bufbuild/protobuf';
import { callEngine } from '../wasmLoader';
import { CryptoObjectType } from '../proto/discocrypto/v1/common_pb';
import {
    ParseOCSPRequestRequestSchema,
    ParseOCSPRequestResponseSchema,
    ParseOCSPResponseRequestSchema,
    ParseOCSPResponseResponseSchema,
} from '../proto/discocrypto/v1/ocsp_pb';
import { ParsedObjectSchema, type ParsedObject } from '../proto/discocrypto/v1/parser_pb';
import type { CryptoHandler } from './index';

class OCSPHandler implements CryptoHandler {
    parse(data: Uint8Array, type: CryptoObjectType): ParsedObject[] {
        switch (type) {
            case CryptoObjectType.OCSP_REQUEST: {
                const req = create(ParseOCSPRequestRequestSchema, { data });
                const res = callEngine('parseOCSPRequest', req, ParseOCSPRequestRequestSchema, ParseOCSPRequestResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'OCSP Request',
                    object: { case: 'ocspRequest', value: res.request! },
                })];
            }
            case CryptoObjectType.OCSP_RESPONSE: {
                const req = create(ParseOCSPResponseRequestSchema, { data });
                const res = callEngine('parseOCSPResponse', req, ParseOCSPResponseRequestSchema, ParseOCSPResponseResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'OCSP Response',
                    object: { case: 'ocspResponse', value: res.response! },
                })];
            }
            default:
                throw new Error(`OCSPHandler: unsupported type ${type}`);
        }
    }
}

export const ocspHandler = new OCSPHandler();
