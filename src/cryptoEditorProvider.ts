import * as vscode from 'vscode';
import * as path from 'path';
import { parsePEM } from './wasmLoader';

export class CryptoFileEditorProvider implements vscode.CustomReadonlyEditorProvider {

    public static readonly viewType = 'discoCryptoViewer.certView';

    constructor(private readonly context: vscode.ExtensionContext) {}

    public static register(context: vscode.ExtensionContext): vscode.Disposable {
        const provider = new CryptoFileEditorProvider(context);
        return vscode.window.registerCustomEditorProvider(
            CryptoFileEditorProvider.viewType,
            provider,
            { supportsMultipleEditorsPerDocument: true }
        );
    }

    async openCustomDocument(uri: vscode.Uri): Promise<vscode.CustomDocument> {
        return { uri, dispose: () => {} };
    }

    async resolveCustomEditor(
        document: vscode.CustomDocument,
        webviewPanel: vscode.WebviewPanel,
        _token: vscode.CancellationToken
    ): Promise<void> {
        const webview = webviewPanel.webview;

        webview.options = {
            enableScripts: true,
            localResourceRoots: [
                vscode.Uri.file(path.join(this.context.extensionPath, 'dist', 'webview')),
            ],
        };

        webview.html = this.getWebviewHtml(webview);

        // Parse the file and send data to the webview once it's ready
        const fileBytes = await vscode.workspace.fs.readFile(document.uri);
        const fileContent = Buffer.from(fileBytes).toString('utf-8');
        const result = parsePEM(fileContent);
        const fileName = path.basename(document.uri.fsPath);

        // Small delay to ensure webview has mounted before receiving data
        setTimeout(() => {
            if (result.ok && result.certs) {
                webview.postMessage({ type: 'certs', fileName, certs: result.certs });
            } else {
                webview.postMessage({ type: 'error', message: result.error ?? 'Unknown parse error' });
            }
        }, 100);
    }

    private getWebviewHtml(webview: vscode.Webview): string {
        const webviewDir = path.join(this.context.extensionPath, 'dist', 'webview');

        const scriptUri = webview.asWebviewUri(
            vscode.Uri.file(path.join(webviewDir, 'main.js'))
        );
        const styleUri = webview.asWebviewUri(
            vscode.Uri.file(path.join(webviewDir, 'style.css'))
        );

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
