import { CryptoObjectType } from '../proto/discocrypto/v1/common_pb';
import type { ParsedObject } from '../proto/discocrypto/v1/parser_pb';

export interface CryptoHandler {
    parse(data: Uint8Array, type: CryptoObjectType, options?: Record<string, any>): ParsedObject[];
}

import { x509Handler } from './x509';
import { keysHandler } from './keys';
import { pemHandler } from './pem';
import { pkcsHandler } from './pkcs';
import { sshHandler } from './ssh';
import { pgpHandler } from './pgp';
import { jwkHandler } from './jwk';
import { ocspHandler } from './ocsp';
import { ctHandler } from './ct';

const registry = new Map<CryptoObjectType, CryptoHandler>([
    // X.509
    [CryptoObjectType.CERTIFICATE, x509Handler],
    [CryptoObjectType.CERTIFICATE_REQUEST, x509Handler],
    [CryptoObjectType.CERTIFICATE_REVOCATION_LIST, x509Handler],
    [CryptoObjectType.X509_ATTRIBUTE_CERTIFICATE, x509Handler],

    // Asymmetric keys
    [CryptoObjectType.RSA_PUBLIC_KEY, keysHandler],
    [CryptoObjectType.RSA_PRIVATE_KEY, keysHandler],
    [CryptoObjectType.EC_PUBLIC_KEY, keysHandler],
    [CryptoObjectType.EC_PRIVATE_KEY, keysHandler],
    [CryptoObjectType.ED25519_PUBLIC_KEY, keysHandler],
    [CryptoObjectType.ED25519_PRIVATE_KEY, keysHandler],
    [CryptoObjectType.DSA_PUBLIC_KEY, keysHandler],
    [CryptoObjectType.DSA_PRIVATE_KEY, keysHandler],
    [CryptoObjectType.DH_PARAMETERS, keysHandler],
    [CryptoObjectType.ECDH_PUBLIC_KEY, keysHandler],
    [CryptoObjectType.ECDH_PRIVATE_KEY, keysHandler],

    // PEM
    [CryptoObjectType.PEM, pemHandler],

    // PKCS / CMS
    [CryptoObjectType.PKCS7, pkcsHandler],
    [CryptoObjectType.PKCS8_PRIVATE_KEY, pkcsHandler],
    [CryptoObjectType.PKCS8_ENCRYPTED_PRIVATE_KEY, pkcsHandler],
    [CryptoObjectType.PKCS12, pkcsHandler],
    [CryptoObjectType.CMS_SIGNED_DATA, pkcsHandler],
    [CryptoObjectType.CMS_ENVELOPED_DATA, pkcsHandler],
    [CryptoObjectType.TIMESTAMP_RESPONSE, pkcsHandler],

    // SSH
    [CryptoObjectType.SSH_PUBLIC_KEY, sshHandler],
    [CryptoObjectType.SSH_PRIVATE_KEY, sshHandler],
    [CryptoObjectType.SSH_CERTIFICATE, sshHandler],

    // PGP
    [CryptoObjectType.PGP_PUBLIC_KEY, pgpHandler],
    [CryptoObjectType.PGP_PRIVATE_KEY, pgpHandler],
    [CryptoObjectType.PGP_SIGNATURE, pgpHandler],

    // JWK / JWT
    [CryptoObjectType.JWK, jwkHandler],
    [CryptoObjectType.JWKS, jwkHandler],
    [CryptoObjectType.JWT, jwkHandler],
    [CryptoObjectType.JWS, jwkHandler],
    [CryptoObjectType.JWE, jwkHandler],

    // OCSP
    [CryptoObjectType.OCSP_REQUEST, ocspHandler],
    [CryptoObjectType.OCSP_RESPONSE, ocspHandler],

    // Certificate Transparency
    [CryptoObjectType.SCT, ctHandler],
]);

export function getHandler(type: CryptoObjectType): CryptoHandler {
    const handler = registry.get(type);
    if (!handler) {
        throw new Error(`No handler registered for crypto object type: ${type}`);
    }
    return handler;
}
