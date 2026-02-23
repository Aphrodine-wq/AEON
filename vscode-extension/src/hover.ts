import * as vscode from 'vscode';
import { DiagnosticsManager } from './diagnostics';

export class AeonHoverProvider implements vscode.HoverProvider {
    constructor(private diagnostics: DiagnosticsManager) {}

    provideHover(
        document: vscode.TextDocument,
        position: vscode.Position
    ): vscode.Hover | undefined {
        const result = this.diagnostics.getResult(document.uri);
        if (!result) {
            return undefined;
        }

        // Check if hovering over a function definition
        const line = document.lineAt(position.line).text;
        const funcMatch = line.match(/(?:def|async\s+def|pure|task)\s+(\w+)\s*\(/);
        if (!funcMatch) {
            return undefined;
        }

        const funcName = funcMatch[1];
        const errCount = (result.errors || []).length;
        const warnCount = (result.warnings || []).length;

        const md = new vscode.MarkdownString();
        md.isTrusted = true;

        if (errCount === 0 && warnCount === 0) {
            md.appendMarkdown(`**$(shield) AEON Verified** — no issues found\n\n`);
            md.appendMarkdown(`Function \`${funcName}\` passed all verification engines.`);
        } else {
            md.appendMarkdown(`**$(shield) AEON Results**\n\n`);
            if (errCount > 0) {
                md.appendMarkdown(`- $(error) **${errCount}** error(s)\n`);
            }
            if (warnCount > 0) {
                md.appendMarkdown(`- $(warning) **${warnCount}** warning(s)\n`);
            }
            md.appendMarkdown(`\n---\n`);

            for (const err of (result.errors || []).slice(0, 5)) {
                md.appendMarkdown(`\n$(error) ${err.message || 'Unknown error'}`);
                if (err.details?.function_signature) {
                    md.appendMarkdown(` \`[${err.details.function_signature}]\``);
                }
                md.appendMarkdown(`\n`);
            }
        }

        return new vscode.Hover(md);
    }
}
