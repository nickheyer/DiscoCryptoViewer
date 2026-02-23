import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { type DescMessage, type MessageShape, fromBinary, toBinary } from '@bufbuild/protobuf';

let engineReady = false;
let engineDead = false;
let extensionContext: vscode.ExtensionContext;

export async function initWasmEngine(context: vscode.ExtensionContext): Promise<void> {
    extensionContext = context;
    await startEngine();
}

async function startEngine(): Promise<void> {
    engineReady = false;
    engineDead = false;

    const wasmDir = path.join(extensionContext.extensionPath, 'dist', 'wasm');
    const wasmExecPath = path.join(wasmDir, 'wasm_exec.js');
    const wasmBinaryPath = path.join(wasmDir, 'engine.wasm');

    require(wasmExecPath);

    // @ts-expect-error - Go class is injected by wasm_exec.js
    const go = new Go();

    const wasmBuffer = fs.readFileSync(wasmBinaryPath);
    const wasmModule = await WebAssembly.compile(wasmBuffer);
    const instance = await WebAssembly.instantiate(wasmModule, go.importObject);

    go.run(instance).then(() => {
        engineReady = false;
        engineDead = true;
        console.error('Disco Crypto Viewer: WASM engine exited unexpectedly');
    });

    engineReady = true;
}

export async function ensureEngine(): Promise<void> {
    if (engineDead) {
        console.log('Disco Crypto Viewer: restarting WASM engine...');
        await startEngine();
    }
    if (!engineReady) {
        throw new Error('WASM engine not initialized');
    }
}

export function callEngine<
    ReqDesc extends DescMessage,
    ResDesc extends DescMessage,
>(
    method: string,
    request: MessageShape<ReqDesc>,
    requestSchema: ReqDesc,
    responseSchema: ResDesc,
): MessageShape<ResDesc> {
    if (!engineReady || engineDead) {
        throw new Error('WASM engine not available');
    }

    const engine = (globalThis as any).DiscoEngine;
    if (!engine || typeof engine[method] !== 'function') {
        throw new Error(`DiscoEngine.${method} is not available`);
    }

    try {
        const reqBytes = toBinary(requestSchema, request);
        const result = engine[method](reqBytes);
        if (result && typeof result === 'object' && 'error' in result) {
            throw new Error(result.error);
        }
        const resBytes = new Uint8Array(result);
        return fromBinary(responseSchema, resBytes);
    } catch (err) {
        if (String(err).includes('Go program has already exited')) {
            engineReady = false;
            engineDead = true;
        }
        throw err;
    }
}
