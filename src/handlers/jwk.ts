import { create } from '@bufbuild/protobuf';
import { callEngine } from '../wasmLoader';
import { CryptoObjectType } from '../proto/discocrypto/v1/common_pb';
import {
    ParseJWKRequestSchema,
    ParseJWKResponseSchema,
    ParseJWKSRequestSchema,
    ParseJWKSResponseSchema,
    ParseJWTRequestSchema,
    ParseJWTResponseSchema,
    ParseJWSRequestSchema,
    ParseJWSResponseSchema,
    ParseJWERequestSchema,
    ParseJWEResponseSchema,
} from '../proto/discocrypto/v1/jwk_pb';
import { ParsedObjectSchema, type ParsedObject } from '../proto/discocrypto/v1/parser_pb';
import type { CryptoHandler } from './index';

class JWKHandler implements CryptoHandler {
    parse(data: Uint8Array, type: CryptoObjectType): ParsedObject[] {
        switch (type) {
            case CryptoObjectType.JWK: {
                const req = create(ParseJWKRequestSchema, { data });
                const res = callEngine('parseJWK', req, ParseJWKRequestSchema, ParseJWKResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'JSON Web Key',
                    object: { case: 'jwk', value: res.jwk! },
                })];
            }
            case CryptoObjectType.JWKS: {
                const req = create(ParseJWKSRequestSchema, { data });
                const res = callEngine('parseJWKS', req, ParseJWKSRequestSchema, ParseJWKSResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'JSON Web Key Set',
                    object: { case: 'jwks', value: res.jwks! },
                })];
            }
            case CryptoObjectType.JWT: {
                const req = create(ParseJWTRequestSchema, { data });
                const res = callEngine('parseJWT', req, ParseJWTRequestSchema, ParseJWTResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'JSON Web Token',
                    object: { case: 'jwt', value: res.jwt! },
                })];
            }
            case CryptoObjectType.JWS: {
                const req = create(ParseJWSRequestSchema, { data });
                const res = callEngine('parseJWS', req, ParseJWSRequestSchema, ParseJWSResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'JSON Web Signature',
                    object: { case: 'jws', value: res.jws! },
                })];
            }
            case CryptoObjectType.JWE: {
                const req = create(ParseJWERequestSchema, { data });
                const res = callEngine('parseJWE', req, ParseJWERequestSchema, ParseJWEResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'JSON Web Encryption',
                    object: { case: 'jwe', value: res.jwe! },
                })];
            }
            default:
                throw new Error(`JWKHandler: unsupported type ${type}`);
        }
    }
}

export const jwkHandler = new JWKHandler();
