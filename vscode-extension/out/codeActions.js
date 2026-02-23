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
exports.AeonCodeActionProvider = void 0;
const vscode = __importStar(require("vscode"));
class AeonCodeActionProvider {
    provideCodeActions(document, range, context) {
        const actions = [];
        for (const diag of context.diagnostics) {
            if (diag.source !== 'AEON') {
                continue;
            }
            const msg = diag.message.toLowerCase();
            // Division by zero → suggest guard
            if (msg.includes('division by zero') || msg.includes('divide by zero')) {
                const line = document.lineAt(diag.range.start.line);
                const divMatch = line.text.match(/\/\s*(\w+)/);
                if (divMatch) {
                    const divisor = divMatch[1];
                    const action = new vscode.CodeAction(`Add guard: requires ${divisor} != 0`, vscode.CodeActionKind.QuickFix);
                    action.diagnostics = [diag];
                    // Find the function definition above this line
                    const funcLine = this.findFunctionAbove(document, diag.range.start.line);
                    if (funcLine !== null) {
                        const indent = this.getIndent(document.lineAt(funcLine).text);
                        const docstringInsert = this.buildRequiresInsert(document, funcLine, indent, `${divisor} != 0`);
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
                const action = new vscode.CodeAction('Add bounds check (requires clause)', vscode.CodeActionKind.QuickFix);
                action.diagnostics = [diag];
                actions.push(action);
            }
            // Generic: re-verify
            const reVerify = new vscode.CodeAction('Re-verify with AEON', vscode.CodeActionKind.QuickFix);
            reVerify.command = {
                command: 'aeon.verifyFile',
                title: 'Re-verify',
            };
            reVerify.diagnostics = [diag];
            actions.push(reVerify);
        }
        return actions;
    }
    findFunctionAbove(document, line) {
        for (let i = line; i >= 0; i--) {
            const text = document.lineAt(i).text;
            if (/(?:def|async\s+def|pure|task)\s+\w+\s*\(/.test(text)) {
                return i;
            }
        }
        return null;
    }
    getIndent(line) {
        const match = line.match(/^(\s*)/);
        return match ? match[1] : '';
    }
    buildRequiresInsert(document, funcLine, indent, clause) {
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
                        edit.insert(document.uri, insertPos, `${bodyIndent}Requires: ${clause}\n`);
                        return edit;
                    }
                }
            }
        }
        // No docstring — insert a new one
        const insertPos = new vscode.Position(funcLine + 1, 0);
        edit.insert(document.uri, insertPos, `${bodyIndent}"""\n${bodyIndent}Requires: ${clause}\n${bodyIndent}"""\n`);
        return edit;
    }
}
exports.AeonCodeActionProvider = AeonCodeActionProvider;
AeonCodeActionProvider.providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];
//# sourceMappingURL=codeActions.js.map