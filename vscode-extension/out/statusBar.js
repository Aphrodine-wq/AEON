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
exports.StatusBarManager = void 0;
const vscode = __importStar(require("vscode"));
class StatusBarManager {
    constructor() {
        this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
        this.item.command = 'aeon.verifyFile';
        this.item.tooltip = 'Click to verify current file with AEON';
        this.setIdle();
        this.item.show();
    }
    setIdle() {
        this.clearResetTimer();
        this.item.text = '$(shield) AEON';
        this.item.backgroundColor = undefined;
    }
    setAnalyzing() {
        this.clearResetTimer();
        this.item.text = '$(loading~spin) AEON Analyzing...';
        this.item.backgroundColor = undefined;
    }
    setResult(result) {
        this.clearResetTimer();
        const errCount = (result.errors || []).length;
        if (errCount === 0) {
            this.item.text = '$(shield) AEON \u2705';
            this.item.backgroundColor = undefined;
        }
        else {
            this.item.text = `$(shield) AEON \u274c ${errCount}`;
            this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        }
        this.resetTimer = setTimeout(() => this.setIdle(), 8000);
    }
    clearResetTimer() {
        if (this.resetTimer) {
            clearTimeout(this.resetTimer);
            this.resetTimer = undefined;
        }
    }
    dispose() {
        this.clearResetTimer();
        this.item.dispose();
    }
}
exports.StatusBarManager = StatusBarManager;
//# sourceMappingURL=statusBar.js.map