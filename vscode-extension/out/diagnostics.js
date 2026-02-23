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
exports.DiagnosticsManager = void 0;
const vscode = __importStar(require("vscode"));
class DiagnosticsManager {
    constructor() {
        this.lastResults = new Map();
        this.collection = vscode.languages.createDiagnosticCollection('aeon');
    }
    apply(result, uri, lineOffset) {
        this.lastResults.set(uri.toString(), result);
        const diagnostics = [];
        // Errors
        for (const err of result.errors || []) {
            const line = this.extractLine(err, lineOffset);
            const col = err.location?.column ?? 0;
            const range = new vscode.Range(line, col, line, 1000);
            const diag = new vscode.Diagnostic(range, err.message || 'Unknown error', vscode.DiagnosticSeverity.Error);
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
            const diag = new vscode.Diagnostic(range, warn.message || 'Warning', vscode.DiagnosticSeverity.Warning);
            diag.source = 'AEON';
            diagnostics.push(diag);
        }
        this.collection.set(uri, diagnostics);
        // Show summary notification
        const errCount = (result.errors || []).length;
        if (errCount === 0) {
            vscode.window.showInformationMessage(`AEON: ${result.summary || 'Verified'}`);
        }
        else {
            vscode.window.showWarningMessage(`AEON: ${result.summary || `${errCount} bug(s) found`}`);
        }
    }
    getResult(uri) {
        return this.lastResults.get(uri.toString());
    }
    getDiagnostics(uri) {
        return this.collection.get(uri) || [];
    }
    extractLine(errorObj, offset) {
        if (errorObj.location) {
            const line = typeof errorObj.location.line === 'number' ? errorObj.location.line : 0;
            return Math.max(0, line - 1 + offset);
        }
        return offset;
    }
    dispose() {
        this.collection.dispose();
    }
}
exports.DiagnosticsManager = DiagnosticsManager;
//# sourceMappingURL=diagnostics.js.map