import { create } from '@bufbuild/protobuf';
import { callEngine } from '../wasmLoader';
import { CryptoObjectType } from '../proto/discocrypto/v1/common_pb';
import {
    DecodePemRequestSchema,
    DecodePemResponseSchema,
} from '../proto/discocrypto/v1/pem_pb';
import { ParsedObjectSchema, type ParsedObject } from '../proto/discocrypto/v1/parser_pb';
import type { CryptoHandler } from './index';

class PemHandler implements CryptoHandler {
    parse(data: Uint8Array, type: CryptoObjectType): ParsedObject[] {
        const req = create(DecodePemRequestSchema, { data });
        const res = callEngine('decodePem', req, DecodePemRequestSchema, DecodePemResponseSchema);
        return [create(ParsedObjectSchema, {
            type,
            label: 'PEM File',
            object: { case: 'pemFile', value: res.pemFile! },
        })];
    }
}

export const pemHandler = new PemHandler();
