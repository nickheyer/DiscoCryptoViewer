import type { Timestamp } from '@bufbuild/protobuf/wkt';
import type { BigInt as ProtoBigInt } from '../proto/discocrypto/v1/common_pb';
import {
  SignatureAlgorithm, PublicKeyAlgorithm, KeyUsage, ExtKeyUsage,
  NamedCurve, HashAlgorithm, Encoding, CryptoObjectType, PemType,
} from '../proto/discocrypto/v1/common_pb';

// ── Byte Formatting ──

export function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexColonFormat(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(':');
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function truncateHex(bytes: Uint8Array, maxBytes = 32): string {
  const hex = hexColonFormat(bytes.slice(0, maxBytes));
  return bytes.length > maxBytes ? hex + '\u2026' : hex;
}

export function byteSize(bytes: Uint8Array): string {
  if (bytes.length < 1024) return `${bytes.length} bytes`;
  return `${(bytes.length / 1024).toFixed(1)} KB`;
}

// ── Number Formatting ──

export function formatBigInt(bi?: ProtoBigInt): string {
  if (!bi?.value?.length) return '0';
  return hexColonFormat(bi.value);
}

export function bigIntToDecimal(bi?: ProtoBigInt): string {
  if (!bi?.value?.length) return '0';
  let result = 0n;
  for (const byte of bi.value) {
    result = (result << 8n) | BigInt(byte);
  }
  return result.toString();
}

// ── Timestamp Formatting ──

export function formatTimestamp(ts?: Timestamp): string {
  if (!ts) return 'N/A';
  const ms = Number(ts.seconds) * 1000 + Math.floor(ts.nanos / 1_000_000);
  return new Date(ms).toISOString().replace('T', ' ').replace('Z', ' UTC');
}

export function isExpired(ts?: Timestamp): boolean {
  if (!ts) return false;
  return Number(ts.seconds) * 1000 < Date.now();
}

export function isNotYetValid(ts?: Timestamp): boolean {
  if (!ts) return false;
  return Number(ts.seconds) * 1000 > Date.now();
}

// ── IP Address ──

export function formatIpAddress(bytes: Uint8Array): string {
  if (bytes.length === 4) return Array.from(bytes).join('.');
  if (bytes.length === 16) {
    const parts: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    }
    return parts.join(':');
  }
  return hexColonFormat(bytes);
}

// ── Enum Name Maps ──

const signatureAlgorithmNames: Record<number, string> = {
  [SignatureAlgorithm.UNSPECIFIED]: 'Unknown',
  [SignatureAlgorithm.MD2_WITH_RSA]: 'MD2 with RSA',
  [SignatureAlgorithm.MD5_WITH_RSA]: 'MD5 with RSA',
  [SignatureAlgorithm.SHA1_WITH_RSA]: 'SHA-1 with RSA',
  [SignatureAlgorithm.SHA256_WITH_RSA]: 'SHA-256 with RSA',
  [SignatureAlgorithm.SHA384_WITH_RSA]: 'SHA-384 with RSA',
  [SignatureAlgorithm.SHA512_WITH_RSA]: 'SHA-512 with RSA',
  [SignatureAlgorithm.DSA_WITH_SHA1]: 'DSA with SHA-1',
  [SignatureAlgorithm.DSA_WITH_SHA256]: 'DSA with SHA-256',
  [SignatureAlgorithm.ECDSA_WITH_SHA1]: 'ECDSA with SHA-1',
  [SignatureAlgorithm.ECDSA_WITH_SHA256]: 'ECDSA with SHA-256',
  [SignatureAlgorithm.ECDSA_WITH_SHA384]: 'ECDSA with SHA-384',
  [SignatureAlgorithm.ECDSA_WITH_SHA512]: 'ECDSA with SHA-512',
  [SignatureAlgorithm.ED25519]: 'Ed25519',
  [SignatureAlgorithm.SHA256_WITH_RSA_PSS]: 'SHA-256 with RSA-PSS',
  [SignatureAlgorithm.SHA384_WITH_RSA_PSS]: 'SHA-384 with RSA-PSS',
  [SignatureAlgorithm.SHA512_WITH_RSA_PSS]: 'SHA-512 with RSA-PSS',
};
export function signatureAlgorithmName(alg: SignatureAlgorithm): string {
  return signatureAlgorithmNames[alg] ?? 'Unknown';
}

const publicKeyAlgorithmNames: Record<number, string> = {
  [PublicKeyAlgorithm.UNSPECIFIED]: 'Unknown',
  [PublicKeyAlgorithm.RSA]: 'RSA',
  [PublicKeyAlgorithm.DSA]: 'DSA',
  [PublicKeyAlgorithm.ECDSA]: 'ECDSA',
  [PublicKeyAlgorithm.ED25519]: 'Ed25519',
};
export function publicKeyAlgorithmName(alg: PublicKeyAlgorithm): string {
  return publicKeyAlgorithmNames[alg] ?? 'Unknown';
}

const keyUsageNames: Record<number, string> = {
  [KeyUsage.DIGITAL_SIGNATURE]: 'Digital Signature',
  [KeyUsage.CONTENT_COMMITMENT]: 'Content Commitment',
  [KeyUsage.KEY_ENCIPHERMENT]: 'Key Encipherment',
  [KeyUsage.DATA_ENCIPHERMENT]: 'Data Encipherment',
  [KeyUsage.KEY_AGREEMENT]: 'Key Agreement',
  [KeyUsage.CERT_SIGN]: 'Certificate Sign',
  [KeyUsage.CRL_SIGN]: 'CRL Sign',
  [KeyUsage.ENCIPHER_ONLY]: 'Encipher Only',
  [KeyUsage.DECIPHER_ONLY]: 'Decipher Only',
};
export function keyUsageName(ku: KeyUsage): string {
  return keyUsageNames[ku] ?? 'Unknown';
}

const extKeyUsageNames: Record<number, string> = {
  [ExtKeyUsage.ANY]: 'Any',
  [ExtKeyUsage.SERVER_AUTH]: 'Server Auth',
  [ExtKeyUsage.CLIENT_AUTH]: 'Client Auth',
  [ExtKeyUsage.CODE_SIGNING]: 'Code Signing',
  [ExtKeyUsage.EMAIL_PROTECTION]: 'Email Protection',
  [ExtKeyUsage.IPSEC_END_SYSTEM]: 'IPSec End System',
  [ExtKeyUsage.IPSEC_TUNNEL]: 'IPSec Tunnel',
  [ExtKeyUsage.IPSEC_USER]: 'IPSec User',
  [ExtKeyUsage.TIME_STAMPING]: 'Time Stamping',
  [ExtKeyUsage.OCSP_SIGNING]: 'OCSP Signing',
  [ExtKeyUsage.MICROSOFT_SERVER_GATED_CRYPTO]: 'MS Server Gated',
  [ExtKeyUsage.NETSCAPE_SERVER_GATED_CRYPTO]: 'NS Server Gated',
  [ExtKeyUsage.MICROSOFT_COMMERCIAL_CODE_SIGNING]: 'MS Commercial Code Signing',
  [ExtKeyUsage.MICROSOFT_KERNEL_CODE_SIGNING]: 'MS Kernel Code Signing',
};
export function extKeyUsageName(eku: ExtKeyUsage): string {
  return extKeyUsageNames[eku] ?? 'Unknown';
}

const namedCurveNames: Record<number, string> = {
  [NamedCurve.UNSPECIFIED]: 'Unknown',
  [NamedCurve.P224]: 'P-224',
  [NamedCurve.P256]: 'P-256',
  [NamedCurve.P384]: 'P-384',
  [NamedCurve.P521]: 'P-521',
  [NamedCurve.X25519]: 'X25519',
  [NamedCurve.SECP256K1]: 'secp256k1',
  [NamedCurve.BRAINPOOL_P256R1]: 'brainpoolP256r1',
  [NamedCurve.BRAINPOOL_P384R1]: 'brainpoolP384r1',
  [NamedCurve.BRAINPOOL_P512R1]: 'brainpoolP512r1',
  [NamedCurve.ED25519]: 'Ed25519',
  [NamedCurve.ED448]: 'Ed448',
  [NamedCurve.X448]: 'X448',
};
export function namedCurveName(curve: NamedCurve): string {
  return namedCurveNames[curve] ?? 'Unknown';
}

const hashAlgorithmNames: Record<number, string> = {
  [HashAlgorithm.UNSPECIFIED]: 'Unknown',
  [HashAlgorithm.MD4]: 'MD4',
  [HashAlgorithm.MD5]: 'MD5',
  [HashAlgorithm.SHA1]: 'SHA-1',
  [HashAlgorithm.SHA224]: 'SHA-224',
  [HashAlgorithm.SHA256]: 'SHA-256',
  [HashAlgorithm.SHA384]: 'SHA-384',
  [HashAlgorithm.SHA512]: 'SHA-512',
  [HashAlgorithm.SHA512_224]: 'SHA-512/224',
  [HashAlgorithm.SHA512_256]: 'SHA-512/256',
  [HashAlgorithm.SHA3_224]: 'SHA3-224',
  [HashAlgorithm.SHA3_256]: 'SHA3-256',
  [HashAlgorithm.SHA3_384]: 'SHA3-384',
  [HashAlgorithm.SHA3_512]: 'SHA3-512',
  [HashAlgorithm.BLAKE2S_256]: 'BLAKE2s-256',
  [HashAlgorithm.BLAKE2B_256]: 'BLAKE2b-256',
  [HashAlgorithm.BLAKE2B_384]: 'BLAKE2b-384',
  [HashAlgorithm.BLAKE2B_512]: 'BLAKE2b-512',
  [HashAlgorithm.RIPEMD160]: 'RIPEMD-160',
};
export function hashAlgorithmName(hash: HashAlgorithm): string {
  return hashAlgorithmNames[hash] ?? 'Unknown';
}

const encodingNames: Record<number, string> = {
  [Encoding.UNSPECIFIED]: 'Unknown',
  [Encoding.PEM]: 'PEM',
  [Encoding.DER]: 'DER',
  [Encoding.OPENSSH]: 'OpenSSH',
  [Encoding.SSH2]: 'SSH2',
  [Encoding.JSON]: 'JSON',
  [Encoding.PKCS12]: 'PKCS#12',
  [Encoding.PKCS7]: 'PKCS#7',
  [Encoding.PGP_ASCII_ARMOR]: 'PGP ASCII Armor',
  [Encoding.PGP_BINARY]: 'PGP Binary',
  [Encoding.JWK]: 'JWK',
  [Encoding.PUTTY]: 'PuTTY',
};
export function encodingName(enc: Encoding): string {
  return encodingNames[enc] ?? 'Unknown';
}

const cryptoObjectTypeNames: Record<number, string> = {
  [CryptoObjectType.UNSPECIFIED]: 'Unknown',
  [CryptoObjectType.CERTIFICATE]: 'X.509 Certificate',
  [CryptoObjectType.CERTIFICATE_REQUEST]: 'Certificate Signing Request',
  [CryptoObjectType.CERTIFICATE_REVOCATION_LIST]: 'Certificate Revocation List',
  [CryptoObjectType.RSA_PUBLIC_KEY]: 'RSA Public Key',
  [CryptoObjectType.RSA_PRIVATE_KEY]: 'RSA Private Key',
  [CryptoObjectType.EC_PUBLIC_KEY]: 'EC Public Key',
  [CryptoObjectType.EC_PRIVATE_KEY]: 'EC Private Key',
  [CryptoObjectType.ED25519_PUBLIC_KEY]: 'Ed25519 Public Key',
  [CryptoObjectType.ED25519_PRIVATE_KEY]: 'Ed25519 Private Key',
  [CryptoObjectType.DSA_PUBLIC_KEY]: 'DSA Public Key',
  [CryptoObjectType.DSA_PRIVATE_KEY]: 'DSA Private Key',
  [CryptoObjectType.DH_PARAMETERS]: 'DH Parameters',
  [CryptoObjectType.ECDH_PUBLIC_KEY]: 'ECDH Public Key',
  [CryptoObjectType.ECDH_PRIVATE_KEY]: 'ECDH Private Key',
  [CryptoObjectType.PKCS7]: 'PKCS#7 / CMS',
  [CryptoObjectType.PKCS8_PRIVATE_KEY]: 'PKCS#8 Private Key',
  [CryptoObjectType.PKCS8_ENCRYPTED_PRIVATE_KEY]: 'PKCS#8 Encrypted Private Key',
  [CryptoObjectType.PKCS12]: 'PKCS#12 Archive',
  [CryptoObjectType.PEM]: 'PEM File',
  [CryptoObjectType.SSH_PUBLIC_KEY]: 'SSH Public Key',
  [CryptoObjectType.SSH_PRIVATE_KEY]: 'SSH Private Key',
  [CryptoObjectType.SSH_CERTIFICATE]: 'SSH Certificate',
  [CryptoObjectType.PGP_PUBLIC_KEY]: 'PGP Public Key',
  [CryptoObjectType.PGP_PRIVATE_KEY]: 'PGP Private Key',
  [CryptoObjectType.PGP_SIGNATURE]: 'PGP Signature',
  [CryptoObjectType.JWK]: 'JSON Web Key',
  [CryptoObjectType.JWKS]: 'JSON Web Key Set',
  [CryptoObjectType.JWT]: 'JSON Web Token',
  [CryptoObjectType.JWS]: 'JSON Web Signature',
  [CryptoObjectType.JWE]: 'JSON Web Encryption',
  [CryptoObjectType.OCSP_REQUEST]: 'OCSP Request',
  [CryptoObjectType.OCSP_RESPONSE]: 'OCSP Response',
  [CryptoObjectType.SCT]: 'Signed Certificate Timestamp',
  [CryptoObjectType.CMS_SIGNED_DATA]: 'CMS Signed Data',
  [CryptoObjectType.CMS_ENVELOPED_DATA]: 'CMS Enveloped Data',
  [CryptoObjectType.X509_ATTRIBUTE_CERTIFICATE]: 'X.509 Attribute Certificate',
  [CryptoObjectType.TIMESTAMP_RESPONSE]: 'Timestamp Response',
};
export function cryptoObjectTypeName(type: CryptoObjectType): string {
  return cryptoObjectTypeNames[type] ?? 'Unknown';
}

const pemTypeNames: Record<number, string> = {
  [PemType.UNSPECIFIED]: 'Unknown',
  [PemType.CERTIFICATE]: 'Certificate',
  [PemType.CERTIFICATE_REQUEST]: 'Certificate Request',
  [PemType.X509_CRL]: 'X.509 CRL',
  [PemType.RSA_PRIVATE_KEY]: 'RSA Private Key',
  [PemType.RSA_PUBLIC_KEY]: 'RSA Public Key',
  [PemType.EC_PRIVATE_KEY]: 'EC Private Key',
  [PemType.EC_PUBLIC_KEY]: 'EC Public Key',
  [PemType.PRIVATE_KEY]: 'Private Key',
  [PemType.PUBLIC_KEY]: 'Public Key',
  [PemType.ENCRYPTED_PRIVATE_KEY]: 'Encrypted Private Key',
  [PemType.OPENSSH_PRIVATE_KEY]: 'OpenSSH Private Key',
  [PemType.DSA_PRIVATE_KEY]: 'DSA Private Key',
  [PemType.DSA_PUBLIC_KEY]: 'DSA Public Key',
  [PemType.DH_PARAMETERS]: 'DH Parameters',
  [PemType.PKCS7]: 'PKCS#7',
  [PemType.CMS]: 'CMS',
  [PemType.ATTRIBUTE_CERTIFICATE]: 'Attribute Certificate',
};
export function pemTypeName(pt: PemType): string {
  return pemTypeNames[pt] ?? 'Unknown';
}

// ── Type-Specific Enum Names ──

export function revocationReasonName(reason: number): string {
  const m: Record<number, string> = {
    0: 'Unspecified', 1: 'Key Compromise', 2: 'CA Compromise',
    3: 'Affiliation Changed', 4: 'Superseded', 5: 'Cessation of Operation',
    6: 'Certificate Hold', 8: 'Remove from CRL', 9: 'Privilege Withdrawn',
    10: 'AA Compromise',
  };
  return m[reason] ?? 'Unknown';
}

export function sshCertTypeName(type: number): string {
  return ({ 1: 'User', 2: 'Host' } as Record<number, string>)[type] ?? 'Unknown';
}

export function pgpKeyAlgorithmName(alg: number): string {
  const m: Record<number, string> = {
    0: 'Unknown', 1: 'RSA (Encrypt Only)', 2: 'RSA (Sign Only)',
    3: 'RSA (Encrypt or Sign)', 4: 'ElGamal', 5: 'DSA',
    6: 'ECDH', 7: 'ECDSA', 8: 'EdDSA',
  };
  return m[alg] ?? 'Unknown';
}

export function pgpSignatureTypeName(type: number): string {
  const m: Record<number, string> = {
    0: 'Unknown', 1: 'Binary', 2: 'Canonical Text', 3: 'Standalone',
    4: 'Generic Cert', 5: 'Persona Cert', 6: 'Casual Cert',
    7: 'Positive Cert', 8: 'Subkey Binding', 9: 'Primary Key Binding',
    10: 'Direct Key', 11: 'Key Revocation', 12: 'Subkey Revocation',
  };
  return m[type] ?? 'Unknown';
}

export function pgpSymmetricAlgorithmName(alg: number): string {
  const m: Record<number, string> = {
    0: 'Unknown', 1: 'IDEA', 2: 'Triple DES', 3: 'CAST5',
    4: 'Blowfish', 5: 'AES-128', 6: 'AES-192', 7: 'AES-256',
    8: 'Twofish', 9: 'ChaCha20-Poly1305',
  };
  return m[alg] ?? 'Unknown';
}

export function pgpKeyFlagName(flag: number): string {
  const m: Record<number, string> = {
    0: 'Unknown', 1: 'Certify', 2: 'Sign', 3: 'Encrypt Communications',
    4: 'Encrypt Storage', 5: 'Split', 6: 'Authenticate', 7: 'Group Key',
  };
  return m[flag] ?? 'Unknown';
}

export function ocspResponseStatusName(status: number): string {
  const m: Record<number, string> = {
    0: 'Successful', 1: 'Malformed Request', 2: 'Internal Error',
    3: 'Try Later', 5: 'Sig Required', 6: 'Unauthorized',
  };
  return m[status] ?? 'Unknown';
}

export function ocspCertStatusName(status: number): string {
  return ({ 0: 'Unknown', 1: 'Good', 2: 'Revoked', 3: 'Unknown' } as Record<number, string>)[status] ?? 'Unknown';
}

export function cmsContentTypeName(type: number): string {
  const m: Record<number, string> = {
    0: 'Unknown', 1: 'Data', 2: 'Signed Data', 3: 'Enveloped Data',
    4: 'Digested Data', 5: 'Encrypted Data', 6: 'Authenticated Data',
  };
  return m[type] ?? 'Unknown';
}

export function pkcs12BagTypeName(type: number): string {
  const m: Record<number, string> = {
    0: 'Unknown', 1: 'Key Bag', 2: 'PKCS#8 Shrouded Key Bag',
    3: 'Cert Bag', 4: 'CRL Bag', 5: 'Secret Bag', 6: 'Safe Contents Bag',
  };
  return m[type] ?? 'Unknown';
}

// ── OID Names ──

const oidNames: Record<string, string> = {
  '2.5.4.3': 'Common Name',
  '2.5.4.4': 'Surname',
  '2.5.4.5': 'Serial Number',
  '2.5.4.6': 'Country',
  '2.5.4.7': 'Locality',
  '2.5.4.8': 'State/Province',
  '2.5.4.10': 'Organization',
  '2.5.4.11': 'Organizational Unit',
  '2.5.4.12': 'Title',
  '2.5.4.42': 'Given Name',
  '2.5.4.46': 'DN Qualifier',
  '2.5.29.14': 'Subject Key Identifier',
  '2.5.29.15': 'Key Usage',
  '2.5.29.17': 'Subject Alternative Name',
  '2.5.29.18': 'Issuer Alternative Name',
  '2.5.29.19': 'Basic Constraints',
  '2.5.29.30': 'Name Constraints',
  '2.5.29.31': 'CRL Distribution Points',
  '2.5.29.32': 'Certificate Policies',
  '2.5.29.33': 'Policy Mappings',
  '2.5.29.35': 'Authority Key Identifier',
  '2.5.29.36': 'Policy Constraints',
  '2.5.29.37': 'Extended Key Usage',
  '2.5.29.54': 'Inhibit anyPolicy',
  '1.3.6.1.5.5.7.1.1': 'Authority Info Access',
  '1.3.6.1.5.5.7.1.11': 'Subject Info Access',
  '1.3.6.1.5.5.7.48.1': 'OCSP',
  '1.3.6.1.5.5.7.48.2': 'CA Issuers',
  '1.3.6.1.5.5.7.2.1': 'CPS',
  '1.3.6.1.5.5.7.2.2': 'User Notice',
  '1.3.6.1.4.1.11129.2.4.2': 'CT Precertificate SCTs',
  '1.3.6.1.4.1.11129.2.4.3': 'CT Precertificate Signing',
  '2.16.840.1.113730.1.1': 'Netscape Cert Type',
  '2.16.840.1.113730.1.13': 'Netscape Comment',
};
export function oidName(oid: string): string {
  return oidNames[oid] ?? oid;
}

// ── Object-to-Accent Color ──

export function objectAccent(caseStr: string): string {
  const m: Record<string, string> = {
    certificate: 'cyan', certificateRequest: 'cyan', crl: 'cyan', attributeCertificate: 'cyan',
    publicKey: 'magenta', privateKey: 'magenta', dhParameters: 'magenta',
    pemFile: 'blue',
    pkcs7: 'blue', pkcs8: 'blue', pkcs8Encrypted: 'blue', pkcs12: 'blue',
    sshPublicKey: 'green', sshPrivateKey: 'green', sshCertificate: 'green',
    pgpPublicKey: 'orange', pgpPrivateKey: 'orange', pgpSignature: 'orange',
    jwk: 'yellow', jwks: 'yellow', jwt: 'yellow', jws: 'yellow', jwe: 'yellow',
    ocspRequest: 'red', ocspResponse: 'red',
    sct: 'purple', timestampResponse: 'purple',
  };
  return m[caseStr] ?? 'cyan';
}
