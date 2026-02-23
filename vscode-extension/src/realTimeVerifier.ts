import * as vscode from 'vscode';
import { Verifier } from './verifier';
import { DiagnosticsManager } from './diagnostics';
import { StatusBarManager } from './statusBar';

/**
 * Real-time verification that runs as you type
 * with intelligent debouncing and background processing
 */
export class RealTimeVerifier {
    private enabled = false;
    private verificationQueue = new Map<string, NodeJS.Timeout>();
    private isVerifying = new Set<string>();
    private readonly debounceMs = 800;

    constructor(
        private verifier: Verifier,
        private diagnosticsManager: DiagnosticsManager,
        private statusBar: StatusBarManager
    ) {}

    enable(): void {
        this.enabled = true;
        vscode.workspace.getConfiguration('aeon').update('realTimeEnabled', true, true);
    }

    disable(): void {
        this.enabled = false;
        vscode.workspace.getConfiguration('aeon').update('realTimeEnabled', false, true);
        
        // Clear all pending verifications
        this.verificationQueue.forEach(timer => clearTimeout(timer));
        this.verificationQueue.clear();
    }

    isEnabled(): boolean {
        return this.enabled;
    }

    verifyDocument(document: vscode.TextDocument): void {
        if (!this.enabled || this.isVerifying.has(document.uri.toString())) {
            return;
        }

        // Cancel previous pending verification for this file
        const existingTimer = this.verificationQueue.get(document.uri.toString());
        if (existingTimer) {
            clearTimeout(existingTimer);
        }

        // Schedule new verification
        const timer = setTimeout(() => {
            this._performVerification(document);
        }, this.debounceMs);

        this.verificationQueue.set(document.uri.toString(), timer);
    }

    private async _performVerification(document: vscode.TextDocument): void {
        const uri = document.uri.toString();
        
        try {
            this.isVerifying.add(uri);
            this.statusBar.setRealTimeVerifying();

            // Use fast verification mode for real-time
            const result = await this.verifier.verifyDocument(document, {
                deepVerify: false,
                profile: 'quick',
                timeout: 3000
            });

            this.diagnosticsManager.updateDiagnostics(document.uri, result, true);
            
            if (result.verified) {
                this.statusBar.setRealTimeVerified();
            } else {
                this.statusBar.setRealTimeErrors(result.errors.length);
            }

        } catch (error) {
            // Don't show errors for real-time verification failures
            // to avoid spamming the user while typing
            console.debug(`Real-time verification failed for ${document.fileName}:`, error);
        } finally {
            this.isVerifying.delete(uri);
            this.verificationQueue.delete(uri);
        }
    }

    dispose(): void {
        this.disable();
    }
}
