import * as vscode from 'vscode';
import { initWasmEngine } from './wasmLoader';
import { CryptoEditorProvider } from './editor';
import { CryptoServer } from './server';

export async function activate(context: vscode.ExtensionContext) {
	console.log('Disco Crypto Viewer: activating...');

	try {
		await initWasmEngine(context);
		console.log('Disco Crypto Viewer: WASM engine loaded');
	} catch (err) {
		vscode.window.showErrorMessage(`Disco Crypto Viewer: Failed to load WASM engine: ${err}`);
		return;
	}

	const server = new CryptoServer();
	context.subscriptions.push(CryptoEditorProvider.register(context, server));
}

export function deactivate() {}
