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
exports.AeonCodeLensProvider = void 0;
const vscode = __importStar(require("vscode"));
const PYTHON_FUNC_RE = /^(\s*)(def|async\s+def)\s+(\w+)\s*\(/gm;
const AEON_FUNC_RE = /^(\s*)(pure|task)\s+(\w+)\s*\(/gm;
class AeonCodeLensProvider {
    constructor() {
        this._onDidChangeCodeLenses = new vscode.EventEmitter();
        this.onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;
    }
    provideCodeLenses(document) {
        const lenses = [];
        const text = document.getText();
        const isPython = document.languageId === 'python';
        const regex = isPython ? PYTHON_FUNC_RE : AEON_FUNC_RE;
        regex.lastIndex = 0;
        let match;
        while ((match = regex.exec(text)) !== null) {
            const line = document.positionAt(match.index).line;
            const range = new vscode.Range(line, 0, line, 0);
            const funcName = match[3];
            lenses.push(new vscode.CodeLens(range, {
                title: '$(shield) Verify',
                tooltip: `Verify function "${funcName}" with AEON`,
                command: 'aeon.verifyFile',
            }));
        }
        return lenses;
    }
}
exports.AeonCodeLensProvider = AeonCodeLensProvider;
//# sourceMappingURL=codeLens.js.map