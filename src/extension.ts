import * as vscode from 'vscode';
import { initWasmEngine } from './wasmLoader';
import { CryptoFileEditorProvider } from './cryptoEditorProvider';

export async function activate(context: vscode.ExtensionContext) {
	console.log('Disco Crypto Viewer: activating...');

	try {
		await initWasmEngine(context);
		console.log('Disco Crypto Viewer: WASM engine loaded');
	} catch (err) {
		vscode.window.showErrorMessage(`Disco Crypto Viewer: Failed to load WASM engine: ${err}`);
		return;
	}

	context.subscriptions.push(CryptoFileEditorProvider.register(context));
}

export function deactivate() {}
