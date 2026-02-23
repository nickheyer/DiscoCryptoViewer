import { create } from '@bufbuild/protobuf';
import { callEngine } from '../wasmLoader';
import { CryptoObjectType } from '../proto/discocrypto/v1/common_pb';
import {
    ParsePGPPublicKeyRequestSchema,
    ParsePGPPublicKeyResponseSchema,
    ParsePGPPrivateKeyRequestSchema,
    ParsePGPPrivateKeyResponseSchema,
    ParsePGPSignatureRequestSchema,
    ParsePGPSignatureResponseSchema,
} from '../proto/discocrypto/v1/pgp_pb';
import { ParsedObjectSchema, type ParsedObject } from '../proto/discocrypto/v1/parser_pb';
import type { CryptoHandler } from './index';

class PGPHandler implements CryptoHandler {
    parse(data: Uint8Array, type: CryptoObjectType): ParsedObject[] {
        switch (type) {
            case CryptoObjectType.PGP_PUBLIC_KEY: {
                const req = create(ParsePGPPublicKeyRequestSchema, { data });
                const res = callEngine('parsePGPPublicKey', req, ParsePGPPublicKeyRequestSchema, ParsePGPPublicKeyResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'PGP Public Key',
                    object: { case: 'pgpPublicKey', value: res.publicKey! },
                })];
            }
            case CryptoObjectType.PGP_PRIVATE_KEY: {
                const req = create(ParsePGPPrivateKeyRequestSchema, { data });
                const res = callEngine('parsePGPPrivateKey', req, ParsePGPPrivateKeyRequestSchema, ParsePGPPrivateKeyResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'PGP Private Key',
                    object: { case: 'pgpPrivateKey', value: res.privateKey! },
                })];
            }
            case CryptoObjectType.PGP_SIGNATURE: {
                const req = create(ParsePGPSignatureRequestSchema, { data });
                const res = callEngine('parsePGPSignature', req, ParsePGPSignatureRequestSchema, ParsePGPSignatureResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'PGP Signature',
                    object: { case: 'pgpSignature', value: res.signature! },
                })];
            }
            default:
                throw new Error(`PGPHandler: unsupported type ${type}`);
        }
    }
}

export const pgpHandler = new PGPHandler();
