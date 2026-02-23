import { create } from '@bufbuild/protobuf';
import { callEngine } from '../wasmLoader';
import { CryptoObjectType } from '../proto/discocrypto/v1/common_pb';
import {
    ParsePublicKeyRequestSchema,
    ParsePublicKeyResponseSchema,
    ParsePrivateKeyRequestSchema,
    ParsePrivateKeyResponseSchema,
    ParseDHParametersRequestSchema,
    ParseDHParametersResponseSchema,
} from '../proto/discocrypto/v1/keys_pb';
import { ParsedObjectSchema, type ParsedObject } from '../proto/discocrypto/v1/parser_pb';
import type { CryptoHandler } from './index';

const PUBLIC_KEY_TYPES = new Set([
    CryptoObjectType.RSA_PUBLIC_KEY,
    CryptoObjectType.EC_PUBLIC_KEY,
    CryptoObjectType.ED25519_PUBLIC_KEY,
    CryptoObjectType.DSA_PUBLIC_KEY,
    CryptoObjectType.ECDH_PUBLIC_KEY,
]);

const PRIVATE_KEY_TYPES = new Set([
    CryptoObjectType.RSA_PRIVATE_KEY,
    CryptoObjectType.EC_PRIVATE_KEY,
    CryptoObjectType.ED25519_PRIVATE_KEY,
    CryptoObjectType.DSA_PRIVATE_KEY,
    CryptoObjectType.ECDH_PRIVATE_KEY,
]);

class KeysHandler implements CryptoHandler {
    parse(data: Uint8Array, type: CryptoObjectType): ParsedObject[] {
        if (PUBLIC_KEY_TYPES.has(type)) {
            const req = create(ParsePublicKeyRequestSchema, { data });
            const res = callEngine('parsePublicKey', req, ParsePublicKeyRequestSchema, ParsePublicKeyResponseSchema);
            return [create(ParsedObjectSchema, {
                type,
                label: 'Public Key',
                object: { case: 'publicKey', value: res.publicKey! },
            })];
        }

        if (PRIVATE_KEY_TYPES.has(type)) {
            const req = create(ParsePrivateKeyRequestSchema, { data });
            const res = callEngine('parsePrivateKey', req, ParsePrivateKeyRequestSchema, ParsePrivateKeyResponseSchema);
            return [create(ParsedObjectSchema, {
                type,
                label: 'Private Key',
                object: { case: 'privateKey', value: res.privateKey! },
            })];
        }

        if (type === CryptoObjectType.DH_PARAMETERS) {
            const req = create(ParseDHParametersRequestSchema, { data });
            const res = callEngine('parseDHParameters', req, ParseDHParametersRequestSchema, ParseDHParametersResponseSchema);
            return [create(ParsedObjectSchema, {
                type,
                label: 'DH Parameters',
                object: { case: 'dhParameters', value: res.parameters! },
            })];
        }

        throw new Error(`KeysHandler: unsupported type ${type}`);
    }
}

export const keysHandler = new KeysHandler();
