import * as vscode from 'vscode';

export interface VerificationError {
    message?: string;
    location?: { line?: number; column?: number };
    details?: {
        function_signature?: string;
        suggestion?: string;
        [key: string]: unknown;
    };
}

export interface VerificationResult {
    errors?: VerificationError[];
    warnings?: VerificationError[];
    summary?: string;
}

export class DiagnosticsManager implements vscode.Disposable {
    private collection: vscode.DiagnosticCollection;
    private lastResults: Map<string, VerificationResult> = new Map();

    constructor() {
        this.collection = vscode.languages.createDiagnosticCollection('aeon');
    }

    apply(result: VerificationResult, uri: vscode.Uri, lineOffset: number): void {
        this.lastResults.set(uri.toString(), result);
        const diagnostics: vscode.Diagnostic[] = [];

        // Errors
        for (const err of result.errors || []) {
            const line = this.extractLine(err, lineOffset);
            const col = err.location?.column ?? 0;
            const range = new vscode.Range(line, col, line, 1000);
            const diag = new vscode.Diagnostic(
                range,
                err.message || 'Unknown error',
                vscode.DiagnosticSeverity.Error
            );
            diag.source = 'AEON';
            diag.code = err.details?.function_signature || undefined;

            if (err.details?.function_signature) {
                diag.message += ` [${err.details.function_signature}]`;
            }

            diagnostics.push(diag);
        }

        // Warnings
        for (const warn of result.warnings || []) {
            const line = this.extractLine(warn, lineOffset);
            const col = warn.location?.column ?? 0;
            const range = new vscode.Range(line, col, line, 1000);
            const diag = new vscode.Diagnostic(
                range,
                warn.message || 'Warning',
                vscode.DiagnosticSeverity.Warning
            );
            diag.source = 'AEON';
            diagnostics.push(diag);
        }

        this.collection.set(uri, diagnostics);

        // Show summary notification
        const errCount = (result.errors || []).length;
        if (errCount === 0) {
            vscode.window.showInformationMessage(`AEON: ${result.summary || 'Verified'}`);
        } else {
            vscode.window.showWarningMessage(
                `AEON: ${result.summary || `${errCount} bug(s) found`}`
            );
        }
    }

    getResult(uri: vscode.Uri): VerificationResult | undefined {
        return this.lastResults.get(uri.toString());
    }

    getDiagnostics(uri: vscode.Uri): readonly vscode.Diagnostic[] {
        return this.collection.get(uri) || [];
    }

    private extractLine(errorObj: VerificationError, offset: number): number {
        if (errorObj.location) {
            const line = typeof errorObj.location.line === 'number' ? errorObj.location.line : 0;
            return Math.max(0, line - 1 + offset);
        }
        return offset;
    }

    dispose(): void {
        this.collection.dispose();
    }
}
