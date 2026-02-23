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
exports.AeonHoverProvider = void 0;
const vscode = __importStar(require("vscode"));
class AeonHoverProvider {
    constructor(diagnostics) {
        this.diagnostics = diagnostics;
    }
    provideHover(document, position) {
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
        }
        else {
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
exports.AeonHoverProvider = AeonHoverProvider;
//# sourceMappingURL=hover.js.map