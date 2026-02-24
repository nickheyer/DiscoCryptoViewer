import * as vscode from 'vscode';
import * as path from 'path';
import type { CryptoServer } from './server';

export class CryptoEditorProvider implements vscode.CustomReadonlyEditorProvider {

    public static readonly viewType = 'discoCryptoViewer.cryptoView';

    constructor(
        private readonly context: vscode.ExtensionContext,
        private readonly server: CryptoServer,
    ) {}

    public static register(
        context: vscode.ExtensionContext,
        server: CryptoServer,
    ): vscode.Disposable {
        const provider = new CryptoEditorProvider(context, server);
        return vscode.window.registerCustomEditorProvider(
            CryptoEditorProvider.viewType,
            provider,
            { supportsMultipleEditorsPerDocument: true },
        );
    }

    async openCustomDocument(uri: vscode.Uri): Promise<vscode.CustomDocument> {
        return { uri, dispose: () => {} };
    }

    async resolveCustomEditor(
        document: vscode.CustomDocument,
        webviewPanel: vscode.WebviewPanel,
        _token: vscode.CancellationToken,
    ): Promise<void> {
        const webview = webviewPanel.webview;

        webview.options = {
            enableScripts: true,
            localResourceRoots: [
                vscode.Uri.file(path.join(this.context.extensionPath, 'dist', 'webview')),
            ],
        };

        webview.html = this.buildHtml(webview);

        const fileBytes = await vscode.workspace.fs.readFile(document.uri);
        const data = new Uint8Array(fileBytes);
        const filename = path.basename(document.uri.fsPath);

        const sendParse = async (options?: Record<string, any>) => {
            try {
                const result = await this.server.parse(data, filename, options);
                webview.postMessage({ type: 'parsed', filename, data: Array.from(result) });
            } catch (err) {
                webview.postMessage({ type: 'error', message: String(err) });
            }
        };

        webview.onDidReceiveMessage((msg) => {
            if (msg.type === 'ready') {
                sendParse();
            } else if (msg.type === 'retry') {
                sendParse(msg);
            }
        });
    }

    private buildHtml(webview: vscode.Webview): string {
        const base = path.join(this.context.extensionPath, 'dist', 'webview');
        const scriptUri = webview.asWebviewUri(vscode.Uri.file(path.join(base, 'main.js')));
        const styleUri = webview.asWebviewUri(vscode.Uri.file(path.join(base, 'index.css')));
        const nonce = getNonce();

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';">
    <link rel="stylesheet" href="${styleUri}">
    <title>Crypto Viewer</title>
</head>
<body>
    <div id="app"></div>
    <script nonce="${nonce}" type="module" src="${scriptUri}"></script>
</body>
</html>`;
    }
}

function getNonce(): string {
    let text = '';
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 32; i++) {
        text += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return text;
}
