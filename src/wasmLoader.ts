import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';

// Type for the global DiscoEngine namespace set by Go WASM
interface DiscoEngine {
    parsePEM(pem: string): string;
}

interface ParseResult {
    ok: boolean;
    certs?: CertInfo[];
    error?: string;
}

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

let engineReady = false;

/**
 * Initializes the Go WASM runtime and loads the engine.
 * Must be called once during extension activation.
 */
export async function initWasmEngine(context: vscode.ExtensionContext): Promise<void> {
    if (engineReady) {
        return;
    }

    const wasmDir = path.join(context.extensionPath, 'dist', 'wasm');
    const wasmExecPath = path.join(wasmDir, 'wasm_exec.js');
    const wasmBinaryPath = path.join(wasmDir, 'engine.wasm');

    // Load Go's wasm_exec.js glue into the current Node.js context
    require(wasmExecPath);

    // @ts-expect-error - Go class is injected by wasm_exec.js
    const go = new Go();

    const wasmBuffer = fs.readFileSync(wasmBinaryPath);
    const wasmModule = await WebAssembly.compile(wasmBuffer);
    const instance = await WebAssembly.instantiate(wasmModule, go.importObject);

    // Run the Go program (non-blocking — it parks on select{})
    go.run(instance);

    engineReady = true;
}

/**
 * Parse PEM-encoded certificate data via the Go WASM engine.
 */
export function parsePEM(pemString: string): ParseResult {
    if (!engineReady) {
        throw new Error('WASM engine not initialized. Call initWasmEngine() first.');
    }

    const engine = (globalThis as any).DiscoEngine as DiscoEngine;
    const rawResult = engine.parsePEM(pemString);
    return JSON.parse(rawResult) as ParseResult;
}
