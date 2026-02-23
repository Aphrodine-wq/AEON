import * as vscode from 'vscode';
import { spawn, ChildProcess } from 'child_process';

export class ServerManager {
    private process: ChildProcess | null = null;

    constructor(private outputChannel: vscode.OutputChannel) {}

    start(): void {
        if (this.process) {
            vscode.window.showInformationMessage('AEON server is already running.');
            return;
        }

        const config = vscode.workspace.getConfiguration('aeon');
        const pythonPath = config.get<string>('pythonPath') || 'python3';
        const aeonPath = config.get<string>('aeonPath') || '';
        const serverUrl = config.get<string>('serverUrl') || 'http://localhost:8000';
        const port = new URL(serverUrl).port || '8000';

        const args = ['-m', 'aeon.api_server', '--port', port];
        const opts: { env: NodeJS.ProcessEnv; cwd?: string } = {
            env: { ...process.env },
        };
        if (aeonPath) {
            opts.cwd = aeonPath;
        }

        this.process = spawn(pythonPath, args, opts);

        this.process.stdout?.on('data', (data: Buffer) => {
            this.outputChannel.appendLine(`[Server] ${data}`);
        });

        this.process.stderr?.on('data', (data: Buffer) => {
            this.outputChannel.appendLine(`[Server] ${data}`);
        });

        this.process.on('close', (code) => {
            this.process = null;
            if (code !== 0 && code !== null) {
                vscode.window.showErrorMessage(`AEON server exited with code ${code}`);
                this.outputChannel.appendLine(`[Server] Exited with code ${code}`);
            }
        });

        this.process.on('error', (err) => {
            this.outputChannel.appendLine(`[Server] Failed to start: ${err.message}`);
            vscode.window.showErrorMessage(`AEON: Failed to start server — ${err.message}`);
            this.process = null;
        });

        vscode.window.showInformationMessage(`AEON server starting on port ${port}...`);
        this.outputChannel.appendLine(`[Server] Starting on port ${port}`);
        this.outputChannel.show(true);
    }

    stop(): void {
        if (this.process) {
            this.process.kill();
            this.process = null;
            vscode.window.showInformationMessage('AEON server stopped.');
            this.outputChannel.appendLine('[Server] Stopped.');
        } else {
            vscode.window.showInformationMessage('No AEON server running.');
        }
    }
}
