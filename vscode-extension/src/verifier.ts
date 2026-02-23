import * as vscode from 'vscode';
import * as http from 'http';
import { spawn } from 'child_process';
import { DiagnosticsManager, VerificationResult } from './diagnostics';
import { StatusBarManager } from './statusBar';

export class Verifier {
    constructor(
        private outputChannel: vscode.OutputChannel,
        private diagnostics: DiagnosticsManager,
        private statusBar: StatusBarManager
    ) {}

    async verifyDocument(document: vscode.TextDocument): Promise<void> {
        const code = document.getText();
        await this.runVerification(code, document.uri, 0);
    }

    async runVerification(code: string, uri: vscode.Uri, lineOffset: number): Promise<void> {
        await vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: 'AEON: Verifying...',
                cancellable: true,
            },
            async (_progress, token) => {
                this.statusBar.setAnalyzing();

                try {
                    // Try API server first
                    const result = await this.tryApiServer(code, uri, token);
                    if (result) {
                        this.diagnostics.apply(result, uri, lineOffset);
                        this.statusBar.setResult(result);
                        return;
                    }

                    if (token.isCancellationRequested) {
                        this.statusBar.setIdle();
                        return;
                    }

                    // Fallback: run Python directly
                    const result2 = await this.runPythonDirectly(code, token);
                    if (result2) {
                        this.diagnostics.apply(result2, uri, lineOffset);
                        this.statusBar.setResult(result2);
                        return;
                    }

                    vscode.window.showErrorMessage(
                        'AEON: Could not connect to server or run Python. ' +
                        'Start the server with "AEON: Start Verification Server" or set aeon.aeonPath.'
                    );
                    this.statusBar.setIdle();
                } catch (err: unknown) {
                    const message = err instanceof Error ? err.message : String(err);
                    vscode.window.showErrorMessage(`AEON: ${message}`);
                    this.statusBar.setIdle();
                }
            }
        );
    }

    private tryApiServer(
        code: string,
        uri: vscode.Uri,
        token: vscode.CancellationToken
    ): Promise<VerificationResult | null> {
        return new Promise((resolve) => {
            const config = vscode.workspace.getConfiguration('aeon');
            const serverUrl = config.get<string>('serverUrl') || 'http://localhost:8000';
            const lang = this.detectLanguage(uri.fsPath);

            const url = new URL(`/verify/${lang}`, serverUrl);
            const body = JSON.stringify({
                source: code,
                deep_verify: config.get<boolean>('deepVerify', true),
            });

            const options: http.RequestOptions = {
                hostname: url.hostname,
                port: url.port,
                path: url.pathname,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(body),
                },
                timeout: 30000,
            };

            const req = http.request(options, (res) => {
                let data = '';
                res.on('data', (chunk: Buffer) => { data += chunk; });
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data) as VerificationResult);
                    } catch {
                        this.outputChannel.appendLine(`[AEON] Failed to parse server response: ${data.slice(0, 200)}`);
                        resolve(null);
                    }
                });
            });

            token.onCancellationRequested(() => {
                req.destroy();
                resolve(null);
            });

            req.on('error', () => resolve(null));
            req.on('timeout', () => { req.destroy(); resolve(null); });
            req.write(body);
            req.end();
        });
    }

    private detectLanguage(fsPath: string): string {
        const ext = fsPath.split('.').pop()?.toLowerCase() || '';
        const langMap: Record<string, string> = {
            'py': 'python',
            'java': 'java',
            'js': 'javascript',
            'jsx': 'javascript',
            'mjs': 'javascript',
            'ts': 'typescript',
            'tsx': 'typescript',
            'go': 'go',
            'rs': 'rust',
            'c': 'c',
            'h': 'c',
            'cpp': 'cpp',
            'hpp': 'cpp',
            'cc': 'cpp',
            'cxx': 'cpp',
            'rb': 'ruby',
            'swift': 'swift',
            'kt': 'kotlin',
            'kts': 'kotlin',
            'php': 'php',
            'scala': 'scala',
            'dart': 'dart',
            'aeon': 'aeon',
        };
        return langMap[ext] || 'python';
    }

    private detectLanguageId(code: string): string {
        // Best-effort detection from code content when no file path available
        if (code.includes('public class ') || code.includes('public static void main')) {
            return 'java';
        }
        if (code.includes('function ') || code.includes('const ') || code.includes('=>')) {
            return 'javascript';
        }
        if (code.includes('def ') || code.includes('import ')) {
            return 'python';
        }
        return 'python';
    }

    private runPythonDirectly(
        code: string,
        token: vscode.CancellationToken
    ): Promise<VerificationResult | null> {
        return new Promise((resolve) => {
            const config = vscode.workspace.getConfiguration('aeon');
            const pythonPath = config.get<string>('pythonPath') || 'python3';
            const aeonPath = config.get<string>('aeonPath') || '';

            if (!aeonPath) {
                resolve(null);
                return;
            }

            const script = `
import sys, json
sys.path.insert(0, ${JSON.stringify(aeonPath)})
from aeon.language_adapter import verify
source = ${JSON.stringify(code)}
language = ${JSON.stringify(this.detectLanguageId(code))}
result = verify(source, language)
print(json.dumps(result.to_dict()))
`;

            const proc = spawn(pythonPath, ['-c', script], {
                timeout: 60000,
                env: { ...process.env },
            });

            token.onCancellationRequested(() => {
                proc.kill();
                resolve(null);
            });

            let stdout = '';
            let stderr = '';
            proc.stdout.on('data', (d: Buffer) => { stdout += d; });
            proc.stderr.on('data', (d: Buffer) => {
                stderr += d;
                this.outputChannel.appendLine(`[AEON Python] ${d}`);
            });
            proc.on('close', () => {
                try {
                    resolve(JSON.parse(stdout.trim()) as VerificationResult);
                } catch {
                    if (stderr) {
                        this.outputChannel.appendLine(`[AEON] Python verification failed: ${stderr.slice(0, 500)}`);
                    }
                    resolve(null);
                }
            });
            proc.on('error', (err) => {
                this.outputChannel.appendLine(`[AEON] Failed to spawn Python: ${err.message}`);
                resolve(null);
            });
        });
    }
}
