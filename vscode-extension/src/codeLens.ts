import * as vscode from 'vscode';

const PYTHON_FUNC_RE = /^(\s*)(def|async\s+def)\s+(\w+)\s*\(/gm;
const AEON_FUNC_RE = /^(\s*)(pure|task)\s+(\w+)\s*\(/gm;

export class AeonCodeLensProvider implements vscode.CodeLensProvider {
    private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
    readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

    provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
        const lenses: vscode.CodeLens[] = [];
        const text = document.getText();
        const isPython = document.languageId === 'python';
        const regex = isPython ? PYTHON_FUNC_RE : AEON_FUNC_RE;

        regex.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = regex.exec(text)) !== null) {
            const line = document.positionAt(match.index).line;
            const range = new vscode.Range(line, 0, line, 0);
            const funcName = match[3];

            lenses.push(
                new vscode.CodeLens(range, {
                    title: '$(shield) Verify',
                    tooltip: `Verify function "${funcName}" with AEON`,
                    command: 'aeon.verifyFile',
                })
            );
        }

        return lenses;
    }
}
