"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.Verifier = void 0;
const vscode = __importStar(require("vscode"));
const http = __importStar(require("http"));
const child_process_1 = require("child_process");
class Verifier {
    constructor(outputChannel, diagnostics, statusBar) {
        this.outputChannel = outputChannel;
        this.diagnostics = diagnostics;
        this.statusBar = statusBar;
    }
    async verifyDocument(document) {
        const code = document.getText();
        await this.runVerification(code, document.uri, 0);
    }
    async runVerification(code, uri, lineOffset) {
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'AEON: Verifying...',
            cancellable: true,
        }, async (_progress, token) => {
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
                vscode.window.showErrorMessage('AEON: Could not connect to server or run Python. ' +
                    'Start the server with "AEON: Start Verification Server" or set aeon.aeonPath.');
                this.statusBar.setIdle();
            }
            catch (err) {
                const message = err instanceof Error ? err.message : String(err);
                vscode.window.showErrorMessage(`AEON: ${message}`);
                this.statusBar.setIdle();
            }
        });
    }
    tryApiServer(code, uri, token) {
        return new Promise((resolve) => {
            const config = vscode.workspace.getConfiguration('aeon');
            const serverUrl = config.get('serverUrl') || 'http://localhost:8000';
            const lang = uri.fsPath.endsWith('.aeon') ? 'aeon' : 'python';
            const url = new URL(`/verify/${lang}`, serverUrl);
            const body = JSON.stringify({
                source: code,
                deep_verify: config.get('deepVerify', true),
            });
            const options = {
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
                res.on('data', (chunk) => { data += chunk; });
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    }
                    catch {
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
    runPythonDirectly(code, token) {
        return new Promise((resolve) => {
            const config = vscode.workspace.getConfiguration('aeon');
            const pythonPath = config.get('pythonPath') || 'python3';
            const aeonPath = config.get('aeonPath') || '';
            if (!aeonPath) {
                resolve(null);
                return;
            }
            const script = `
import sys, json
sys.path.insert(0, ${JSON.stringify(aeonPath)})
from aeon.python_adapter import verify_python
source = ${JSON.stringify(code)}
result = verify_python(source)
print(json.dumps(result.to_dict()))
`;
            const proc = (0, child_process_1.spawn)(pythonPath, ['-c', script], {
                timeout: 60000,
                env: { ...process.env },
            });
            token.onCancellationRequested(() => {
                proc.kill();
                resolve(null);
            });
            let stdout = '';
            let stderr = '';
            proc.stdout.on('data', (d) => { stdout += d; });
            proc.stderr.on('data', (d) => {
                stderr += d;
                this.outputChannel.appendLine(`[AEON Python] ${d}`);
            });
            proc.on('close', () => {
                try {
                    resolve(JSON.parse(stdout.trim()));
                }
                catch {
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
exports.Verifier = Verifier;
//# sourceMappingURL=verifier.js.map