import * as vscode from 'vscode';
import { VerificationResult } from './diagnostics';

export class StatusBarManager implements vscode.Disposable {
    private item: vscode.StatusBarItem;
    private resetTimer: ReturnType<typeof setTimeout> | undefined;

    constructor() {
        this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
        this.item.command = 'aeon.verifyFile';
        this.item.tooltip = 'Click to verify current file with AEON';
        this.setIdle();
        this.item.show();
    }

    setIdle(): void {
        this.clearResetTimer();
        this.item.text = '$(shield) AEON';
        this.item.backgroundColor = undefined;
    }

    setAnalyzing(): void {
        this.clearResetTimer();
        this.item.text = '$(loading~spin) AEON Analyzing...';
        this.item.backgroundColor = undefined;
    }

    setResult(result: VerificationResult): void {
        this.clearResetTimer();
        const errCount = (result.errors || []).length;

        if (errCount === 0) {
            this.item.text = '$(shield) AEON \u2705';
            this.item.backgroundColor = undefined;
        } else {
            this.item.text = `$(shield) AEON \u274c ${errCount}`;
            this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        }

        this.resetTimer = setTimeout(() => this.setIdle(), 8000);
    }

    private clearResetTimer(): void {
        if (this.resetTimer) {
            clearTimeout(this.resetTimer);
            this.resetTimer = undefined;
        }
    }

    dispose(): void {
        this.clearResetTimer();
        this.item.dispose();
    }
}
