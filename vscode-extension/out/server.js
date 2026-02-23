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
exports.ServerManager = void 0;
const vscode = __importStar(require("vscode"));
const child_process_1 = require("child_process");
class ServerManager {
    constructor(outputChannel) {
        this.outputChannel = outputChannel;
        this.process = null;
    }
    start() {
        if (this.process) {
            vscode.window.showInformationMessage('AEON server is already running.');
            return;
        }
        const config = vscode.workspace.getConfiguration('aeon');
        const pythonPath = config.get('pythonPath') || 'python3';
        const aeonPath = config.get('aeonPath') || '';
        const serverUrl = config.get('serverUrl') || 'http://localhost:8000';
        const port = new URL(serverUrl).port || '8000';
        const args = ['-m', 'aeon.api_server', '--port', port];
        const opts = {
            env: { ...process.env },
        };
        if (aeonPath) {
            opts.cwd = aeonPath;
        }
        this.process = (0, child_process_1.spawn)(pythonPath, args, opts);
        this.process.stdout?.on('data', (data) => {
            this.outputChannel.appendLine(`[Server] ${data}`);
        });
        this.process.stderr?.on('data', (data) => {
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
    stop() {
        if (this.process) {
            this.process.kill();
            this.process = null;
            vscode.window.showInformationMessage('AEON server stopped.');
            this.outputChannel.appendLine('[Server] Stopped.');
        }
        else {
            vscode.window.showInformationMessage('No AEON server running.');
        }
    }
}
exports.ServerManager = ServerManager;
//# sourceMappingURL=server.js.map