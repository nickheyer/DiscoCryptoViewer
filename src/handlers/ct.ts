import { create } from '@bufbuild/protobuf';
import { callEngine } from '../wasmLoader';
import { CryptoObjectType } from '../proto/discocrypto/v1/common_pb';
import {
    ParseSCTRequestSchema,
    ParseSCTResponseSchema,
} from '../proto/discocrypto/v1/ct_pb';
import { ParsedObjectSchema, type ParsedObject } from '../proto/discocrypto/v1/parser_pb';
import type { CryptoHandler } from './index';

class CTHandler implements CryptoHandler {
    parse(data: Uint8Array, type: CryptoObjectType): ParsedObject[] {
        const req = create(ParseSCTRequestSchema, { data });
        const res = callEngine('parseSCT', req, ParseSCTRequestSchema, ParseSCTResponseSchema);
        return [create(ParsedObjectSchema, {
            type,
            label: 'Signed Certificate Timestamp',
            object: { case: 'sct', value: res.sct! },
        })];
    }
}

export const ctHandler = new CTHandler();
