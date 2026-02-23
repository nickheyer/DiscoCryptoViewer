import { create } from '@bufbuild/protobuf';
import { callEngine } from '../wasmLoader';
import { CryptoObjectType } from '../proto/discocrypto/v1/common_pb';
import {
    ParsePKCS7RequestSchema,
    ParsePKCS7ResponseSchema,
    ParsePKCS8RequestSchema,
    ParsePKCS8ResponseSchema,
    ParsePKCS12RequestSchema,
    ParsePKCS12ResponseSchema,
    ParseTimestampRequestSchema,
    ParseTimestampResponseSchema,
} from '../proto/discocrypto/v1/pkcs_pb';
import { ParsedObjectSchema, type ParsedObject } from '../proto/discocrypto/v1/parser_pb';
import type { CryptoHandler } from './index';

class PKCSHandler implements CryptoHandler {
    parse(data: Uint8Array, type: CryptoObjectType, options?: Record<string, any>): ParsedObject[] {
        const passphrase = (options?.passphrase as string) ?? '';
        switch (type) {
            case CryptoObjectType.PKCS7:
            case CryptoObjectType.CMS_SIGNED_DATA:
            case CryptoObjectType.CMS_ENVELOPED_DATA: {
                const req = create(ParsePKCS7RequestSchema, { data });
                const res = callEngine('parsePKCS7', req, ParsePKCS7RequestSchema, ParsePKCS7ResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'PKCS#7 / CMS',
                    object: { case: 'pkcs7', value: res.pkcs7! },
                })];
            }
            case CryptoObjectType.PKCS8_PRIVATE_KEY:
            case CryptoObjectType.PKCS8_ENCRYPTED_PRIVATE_KEY: {
                const req = create(ParsePKCS8RequestSchema, { data, passphrase: passphrase ?? '' });
                const res = callEngine('parsePKCS8', req, ParsePKCS8RequestSchema, ParsePKCS8ResponseSchema);
                if (res.result.case === 'privateKeyInfo') {
                    return [create(ParsedObjectSchema, {
                        type,
                        label: 'PKCS#8 Private Key',
                        object: { case: 'pkcs8', value: res.result.value },
                    })];
                }
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'PKCS#8 Encrypted Private Key',
                    object: { case: 'pkcs8Encrypted', value: res.result.value! },
                })];
            }
            case CryptoObjectType.PKCS12: {
                const req = create(ParsePKCS12RequestSchema, { data, passphrase: passphrase ?? '' });
                const res = callEngine('parsePKCS12', req, ParsePKCS12RequestSchema, ParsePKCS12ResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'PKCS#12 / PFX',
                    object: { case: 'pkcs12', value: res.pkcs12! },
                })];
            }
            case CryptoObjectType.TIMESTAMP_RESPONSE: {
                const req = create(ParseTimestampRequestSchema, { data });
                const res = callEngine('parseTimestamp', req, ParseTimestampRequestSchema, ParseTimestampResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'Timestamp Response',
                    object: { case: 'timestampResponse', value: res.timestamp! },
                })];
            }
            default:
                throw new Error(`PKCSHandler: unsupported type ${type}`);
        }
    }
}

export const pkcsHandler = new PKCSHandler();
