export interface CertInfo {
    subject: string;
    issuer: string;
    serialNumber: string;
    notBefore: string;
    notAfter: string;
    signatureAlgorithm: string;
    publicKeyAlgorithm: string;
    publicKeySize: number;
    isCA: boolean;
    dnsNames: string[] | null;
    emailAddresses: string[] | null;
    ipAddresses: string[] | null;
    keyUsages: string[] | null;
    extKeyUsages: string[] | null;
    version: number;
}

export type MessageFromExtension =
    | { type: 'certs'; fileName: string; certs: CertInfo[] }
    | { type: 'error'; message: string };
