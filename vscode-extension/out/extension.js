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
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const verifier_1 = require("./verifier");
const diagnostics_1 = require("./diagnostics");
const server_1 = require("./server");
const statusBar_1 = require("./statusBar");
const codeLens_1 = require("./codeLens");
const hover_1 = require("./hover");
const codeActions_1 = require("./codeActions");
let verifier;
let diagnosticsManager;
let serverManager;
let statusBar;
let outputChannel;
let saveDebounceTimer;
const SAVE_DEBOUNCE_MS = 500;
function activate(context) {
    outputChannel = vscode.window.createOutputChannel('AEON');
    context.subscriptions.push(outputChannel);
    diagnosticsManager = new diagnostics_1.DiagnosticsManager();
    context.subscriptions.push(diagnosticsManager);
    statusBar = new statusBar_1.StatusBarManager();
    context.subscriptions.push(statusBar);
    serverManager = new server_1.ServerManager(outputChannel);
    verifier = new verifier_1.Verifier(outputChannel, diagnosticsManager, statusBar);
    // Commands
    context.subscriptions.push(vscode.commands.registerCommand('aeon.verifyFile', () => verifyCurrentFile()), vscode.commands.registerCommand('aeon.verifySelection', () => verifySelection()), vscode.commands.registerCommand('aeon.startServer', () => serverManager.start()), vscode.commands.registerCommand('aeon.stopServer', () => serverManager.stop()), vscode.commands.registerCommand('aeon.showOutput', () => outputChannel.show()));
    // CodeLens
    const codeLensProvider = new codeLens_1.AeonCodeLensProvider();
    context.subscriptions.push(vscode.languages.registerCodeLensProvider([{ language: 'python' }, { language: 'aeon' }], codeLensProvider));
    // Hover provider
    const hoverProvider = new hover_1.AeonHoverProvider(diagnosticsManager);
    context.subscriptions.push(vscode.languages.registerHoverProvider([{ language: 'python' }, { language: 'aeon' }], hoverProvider));
    // Code action provider
    const codeActionProvider = new codeActions_1.AeonCodeActionProvider();
    context.subscriptions.push(vscode.languages.registerCodeActionsProvider([{ language: 'python' }, { language: 'aeon' }], codeActionProvider, { providedCodeActionKinds: codeActions_1.AeonCodeActionProvider.providedCodeActionKinds }));
    // Verify on save (debounced)
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument((doc) => {
        const config = vscode.workspace.getConfiguration('aeon');
        if (config.get('verifyOnSave') && doc.languageId === 'python') {
            if (saveDebounceTimer) {
                clearTimeout(saveDebounceTimer);
            }
            saveDebounceTimer = setTimeout(() => {
                verifier.verifyDocument(doc);
            }, SAVE_DEBOUNCE_MS);
        }
    }));
    outputChannel.appendLine('AEON Verify extension activated.');
}
async function verifyCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active editor');
        return;
    }
    await verifier.verifyDocument(editor.document);
}
async function verifySelection() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.selection.isEmpty) {
        vscode.window.showWarningMessage('No text selected');
        return;
    }
    const code = editor.document.getText(editor.selection);
    const startLine = editor.selection.start.line;
    await verifier.runVerification(code, editor.document.uri, startLine);
}
function deactivate() {
    serverManager?.stop();
}
//# sourceMappingURL=extension.js.map