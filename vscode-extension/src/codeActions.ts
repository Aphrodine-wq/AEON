import * as vscode from 'vscode';

export class AeonCodeActionProvider implements vscode.CodeActionProvider {
    static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range,
        context: vscode.CodeActionContext
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diag of context.diagnostics) {
            if (diag.source !== 'AEON') {
                continue;
            }

            const msg = diag.message.toLowerCase();
            const line = document.lineAt(diag.range.start.line);

            // Division by zero → suggest guard
            if (msg.includes('division by zero') || msg.includes('divide by zero')) {
                const divMatch = line.text.match(/\/\s*(\w+)/);
                if (divMatch) {
                    const divisor = divMatch[1];
                    const action = new vscode.CodeAction(
                        `Add guard: requires ${divisor} != 0`,
                        vscode.CodeActionKind.QuickFix
                    );
                    action.diagnostics = [diag];

                    // Find the function definition above this line
                    const funcLine = this.findFunctionAbove(document, diag.range.start.line);
                    if (funcLine !== null) {
                        const indent = this.getIndent(document.lineAt(funcLine).text);
                        const docstringInsert = this.buildRequiresInsert(
                            document, funcLine, indent, `${divisor} != 0`
                        );
                        if (docstringInsert) {
                            action.edit = docstringInsert;
                        }
                    }

                    action.isPreferred = true;
                    actions.push(action);
                }
            }

            // Overflow → suggest bounds check
            if (msg.includes('overflow')) {
                const action = new vscode.CodeAction(
                    'Add bounds check (requires clause)',
                    vscode.CodeActionKind.QuickFix
                );
                action.diagnostics = [diag];
                actions.push(action);
            }

            // Null / None access → suggest guard
            if (msg.includes('null') || msg.includes('none') || msg.includes('nonetype')) {
                const varMatch = line.text.match(/(\w+)\s*\./);
                const varName = varMatch ? varMatch[1] : 'value';
                const action = new vscode.CodeAction(
                    `Add null check for '${varName}'`,
                    vscode.CodeActionKind.QuickFix
                );
                action.diagnostics = [diag];

                const edit = new vscode.WorkspaceEdit();
                const indent = this.getIndent(line.text);
                const langId = document.languageId;
                let guard: string;
                if (langId === 'python') {
                    guard = `${indent}if ${varName} is None:\n${indent}    raise ValueError("${varName} must not be None")\n`;
                } else if (langId === 'javascript' || langId === 'typescript' || langId === 'javascriptreact' || langId === 'typescriptreact') {
                    guard = `${indent}if (${varName} == null) { throw new Error("${varName} must not be null"); }\n`;
                } else if (langId === 'java' || langId === 'kotlin') {
                    guard = `${indent}Objects.requireNonNull(${varName}, "${varName} must not be null");\n`;
                } else {
                    guard = `${indent}/* AEON: add null check for ${varName} */\n`;
                }
                edit.insert(document.uri, new vscode.Position(diag.range.start.line, 0), guard);
                action.edit = edit;
                action.isPreferred = true;
                actions.push(action);
            }

            // Taint / injection → suggest sanitization
            if (msg.includes('taint') || msg.includes('injection') || msg.includes('xss')) {
                const action = new vscode.CodeAction(
                    'Add input sanitization (AEON security fix)',
                    vscode.CodeActionKind.QuickFix
                );
                action.diagnostics = [diag];

                const edit = new vscode.WorkspaceEdit();
                const indent = this.getIndent(line.text);
                const langId = document.languageId;
                let comment: string;
                if (langId === 'python') {
                    comment = `${indent}# AEON: Sanitize user input — use parameterized queries or escape output\n`;
                } else {
                    comment = `${indent}// AEON: Sanitize user input — use parameterized queries or escape output\n`;
                }
                edit.insert(document.uri, new vscode.Position(diag.range.start.line, 0), comment);
                action.edit = edit;
                actions.push(action);
            }

            // Information flow / secret leak
            if (msg.includes('secret') || msg.includes('information flow') || msg.includes('sensitive')) {
                const action = new vscode.CodeAction(
                    'Mask sensitive data before output',
                    vscode.CodeActionKind.QuickFix
                );
                action.diagnostics = [diag];
                actions.push(action);
            }

            // Race condition
            if (msg.includes('race') || msg.includes('concurrent') || msg.includes('lock')) {
                const action = new vscode.CodeAction(
                    'Add synchronization guard',
                    vscode.CodeActionKind.QuickFix
                );
                action.diagnostics = [diag];
                actions.push(action);
            }

            // Generic: re-verify
            const reVerify = new vscode.CodeAction(
                'Re-verify with AEON',
                vscode.CodeActionKind.QuickFix
            );
            reVerify.command = {
                command: 'aeon.verifyFile',
                title: 'Re-verify',
            };
            reVerify.diagnostics = [diag];
            actions.push(reVerify);
        }

        return actions;
    }

    private findFunctionAbove(document: vscode.TextDocument, line: number): number | null {
        for (let i = line; i >= 0; i--) {
            const text = document.lineAt(i).text;
            if (/(?:def|async\s+def|pure|task|func|fn|fun|function|public\s+\w+|private\s+\w+|static\s+\w+)\s+\w+\s*[\(<]/.test(text)) {
                return i;
            }
        }
        return null;
    }

    private getIndent(line: string): string {
        const match = line.match(/^(\s*)/);
        return match ? match[1] : '';
    }

    private buildRequiresInsert(
        document: vscode.TextDocument,
        funcLine: number,
        indent: string,
        clause: string
    ): vscode.WorkspaceEdit | null {
        const edit = new vscode.WorkspaceEdit();
        const bodyIndent = indent + '    ';

        // Check if there's already a docstring
        const nextLine = funcLine + 1;
        if (nextLine < document.lineCount) {
            const nextText = document.lineAt(nextLine).text.trim();
            if (nextText.startsWith('"""') || nextText.startsWith("'''")) {
                // Insert Requires into existing docstring before closing quotes
                for (let i = nextLine; i < document.lineCount; i++) {
                    const t = document.lineAt(i).text;
                    if (i > nextLine && (t.trim().endsWith('"""') || t.trim().endsWith("'''"))) {
                        const insertPos = new vscode.Position(i, 0);
                        edit.insert(
                            document.uri,
                            insertPos,
                            `${bodyIndent}Requires: ${clause}\n`
                        );
                        return edit;
                    }
                }
            }
        }

        // No docstring — insert a new one
        const insertPos = new vscode.Position(funcLine + 1, 0);
        edit.insert(
            document.uri,
            insertPos,
            `${bodyIndent}"""\n${bodyIndent}Requires: ${clause}\n${bodyIndent}"""\n`
        );
        return edit;
    }
}
