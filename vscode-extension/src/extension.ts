import * as vscode from 'vscode';
import { Verifier } from './verifier';
import { DiagnosticsManager } from './diagnostics';
import { ServerManager } from './server';
import { StatusBarManager } from './statusBar';
import { AeonCodeLensProvider } from './codeLens';
import { AeonHoverProvider } from './hover';
import { AeonCodeActionProvider } from './codeActions';
import { RealTimeVerifier } from './realTimeVerifier';
import { ProjectAnalyzer } from './projectAnalyzer';
import { MetricsCollector } from './metricsCollector';

let verifier: Verifier;
let diagnosticsManager: DiagnosticsManager;
let serverManager: ServerManager;
let statusBar: StatusBarManager;
let realTimeVerifier: RealTimeVerifier;
let projectAnalyzer: ProjectAnalyzer;
let metricsCollector: MetricsCollector;
let outputChannel: vscode.OutputChannel;

let saveDebounceTimer: NodeJS.Timeout | undefined;
let changeDebounceTimer: NodeJS.Timeout | undefined;
const SAVE_DEBOUNCE_MS = 500;
const CHANGE_DEBOUNCE_MS = 1000;

export function activate(context: vscode.ExtensionContext): void {
    outputChannel = vscode.window.createOutputChannel('AEON');
    context.subscriptions.push(outputChannel);

    diagnosticsManager = new DiagnosticsManager();
    context.subscriptions.push(diagnosticsManager);

    statusBar = new StatusBarManager();
    context.subscriptions.push(statusBar);

    serverManager = new ServerManager(outputChannel);
    verifier = new Verifier(outputChannel, diagnosticsManager, statusBar);

    // Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('aeon.verifyFile', () => verifyCurrentFile()),
        vscode.commands.registerCommand('aeon.verifySelection', () => verifySelection()),
        vscode.commands.registerCommand('aeon.startServer', () => serverManager.start()),
        vscode.commands.registerCommand('aeon.stopServer', () => serverManager.stop()),
        vscode.commands.registerCommand('aeon.showOutput', () => outputChannel.show()),
    );

    // Supported languages for verification
    const supportedLanguages = [
        { language: 'python' }, { language: 'aeon' },
        { language: 'java' }, { language: 'javascript' }, { language: 'javascriptreact' },
        { language: 'typescript' }, { language: 'typescriptreact' },
        { language: 'go' }, { language: 'rust' },
        { language: 'c' }, { language: 'cpp' },
        { language: 'ruby' }, { language: 'swift' },
        { language: 'kotlin' }, { language: 'php' },
        { language: 'scala' }, { language: 'dart' },
    ];

    // CodeLens
    const codeLensProvider = new AeonCodeLensProvider();
    context.subscriptions.push(
        vscode.languages.registerCodeLensProvider(supportedLanguages, codeLensProvider)
    );

    // Hover provider
    const hoverProvider = new AeonHoverProvider(diagnosticsManager);
    context.subscriptions.push(
        vscode.languages.registerHoverProvider(supportedLanguages, hoverProvider)
    );

    // Code action provider
    const codeActionProvider = new AeonCodeActionProvider();
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            supportedLanguages,
            codeActionProvider,
            { providedCodeActionKinds: AeonCodeActionProvider.providedCodeActionKinds }
        )
    );

    // Supported language IDs for verify-on-save
    const verifyOnSaveLanguages = new Set([
        'python', 'aeon', 'java', 'javascript', 'javascriptreact',
        'typescript', 'typescriptreact', 'go', 'rust', 'c', 'cpp',
        'ruby', 'swift', 'kotlin', 'php', 'scala', 'dart',
    ]);

    // Verify on save (debounced) — all supported languages
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((doc) => {
            const config = vscode.workspace.getConfiguration('aeon');
            if (config.get<boolean>('verifyOnSave') && verifyOnSaveLanguages.has(doc.languageId)) {
                if (saveDebounceTimer) {
                    clearTimeout(saveDebounceTimer);
                }
                saveDebounceTimer = setTimeout(() => {
                    verifier.verifyDocument(doc);
                }, SAVE_DEBOUNCE_MS);
            }
        })
    );

    outputChannel.appendLine('AEON Verify extension activated.');
}

async function verifyCurrentFile(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active editor');
        return;
    }
    await verifier.verifyDocument(editor.document);
}

async function verifySelection(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.selection.isEmpty) {
        vscode.window.showWarningMessage('No text selected');
        return;
    }
    const code = editor.document.getText(editor.selection);
    const startLine = editor.selection.start.line;
    await verifier.runVerification(code, editor.document.uri, startLine);
}

export function deactivate(): void {
    serverManager?.stop();
}
