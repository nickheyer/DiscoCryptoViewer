import { create } from '@bufbuild/protobuf';
import { callEngine } from '../wasmLoader';
import { CryptoObjectType } from '../proto/discocrypto/v1/common_pb';
import {
    ParseSSHPublicKeyRequestSchema,
    ParseSSHPublicKeyResponseSchema,
    ParseSSHPrivateKeyRequestSchema,
    ParseSSHPrivateKeyResponseSchema,
    ParseSSHCertificateRequestSchema,
    ParseSSHCertificateResponseSchema,
} from '../proto/discocrypto/v1/ssh_pb';
import { ParsedObjectSchema, type ParsedObject } from '../proto/discocrypto/v1/parser_pb';
import type { CryptoHandler } from './index';

class SSHHandler implements CryptoHandler {
    parse(data: Uint8Array, type: CryptoObjectType): ParsedObject[] {
        switch (type) {
            case CryptoObjectType.SSH_PUBLIC_KEY: {
                const req = create(ParseSSHPublicKeyRequestSchema, { data });
                const res = callEngine('parseSSHPublicKey', req, ParseSSHPublicKeyRequestSchema, ParseSSHPublicKeyResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'SSH Public Key',
                    object: { case: 'sshPublicKey', value: res.publicKey! },
                })];
            }
            case CryptoObjectType.SSH_PRIVATE_KEY: {
                const req = create(ParseSSHPrivateKeyRequestSchema, { data });
                const res = callEngine('parseSSHPrivateKey', req, ParseSSHPrivateKeyRequestSchema, ParseSSHPrivateKeyResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'SSH Private Key',
                    object: { case: 'sshPrivateKey', value: res.privateKey! },
                })];
            }
            case CryptoObjectType.SSH_CERTIFICATE: {
                const req = create(ParseSSHCertificateRequestSchema, { data });
                const res = callEngine('parseSSHCertificate', req, ParseSSHCertificateRequestSchema, ParseSSHCertificateResponseSchema);
                return [create(ParsedObjectSchema, {
                    type,
                    label: 'SSH Certificate',
                    object: { case: 'sshCertificate', value: res.certificate! },
                })];
            }
            default:
                throw new Error(`SSHHandler: unsupported type ${type}`);
        }
    }
}

export const sshHandler = new SSHHandler();
