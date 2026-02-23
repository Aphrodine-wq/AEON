# AEON Verify — VS Code Extension

[![Version](https://img.shields.io/visual-studio-marketplace/v/aeon-lang.aeon-verify)](https://marketplace.visualstudio.com/items?itemName=aeon-lang.aeon-verify)
[![Installs](https://img.shields.io/visual-studio-marketplace/i/aeon-lang.aeon-verify)](https://marketplace.visualstudio.com/items?itemName=aeon-lang.aeon-verify)

Mathematically verify Python code using **10 formal verification engines**, directly in VS Code. Catch division-by-zero, contract violations, termination issues, and more — with red squiggles, quick fixes, and per-function CodeLens.

<!-- TODO: Add a GIF/screenshot here showing inline diagnostics on a Python file -->
<!-- ![AEON Verify in action](images/demo.gif) -->

## Features

- **Verify on command** — `Cmd+Shift+A` (`Ctrl+Shift+A` on Windows/Linux) to verify the current file
- **Inline diagnostics** — bugs appear as red squiggles with engine attribution and details
- **CodeLens** — "Verify" button appears above every function definition
- **Hover tooltips** — hover over a verified function to see its results inline
- **Quick fixes** — code actions suggest `requires` guards for common bugs (e.g., division by zero)
- **Context menu** — right-click to verify the current file or just the selected code
- **Verify on save** — optional auto-verification (debounced) when you save
- **Status bar** — shows verification status at a glance with error counts
- **Output channel** — full server and analysis logs available in the Output panel
- **Syntax highlighting** — full TextMate grammar for `.aeon` files (keywords, types, contracts, comments)

## Quick Start

### Option A: API Server (recommended)

1. Start the AEON server:
   ```bash
   cd /path/to/AEON
   python3 -m aeon.api_server --port 8000
   ```
2. Open a Python file in VS Code and press `Cmd+Shift+A` — done.

You can also start/stop the server from within VS Code using the **AEON: Start Verification Server** command.

### Option B: Direct Python (no server)

Set `aeon.aeonPath` in your VS Code settings to point to the AEON project root:

```json
{
  "aeon.aeonPath": "/path/to/AEON"
}
```

The extension will call the AEON Python module directly (slower, but no server needed).

## Installation

### From Source

```bash
cd vscode-extension
npm install
npm run compile
npx vsce package
code --install-extension aeon-verify-0.2.0.vsix
```

### Development

```bash
cd vscode-extension
npm install
npm run watch    # recompiles on file changes
# Press F5 in VS Code to launch Extension Development Host
```

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `aeon.serverUrl` | `http://localhost:8000` | AEON API server URL |
| `aeon.pythonPath` | `python3` | Python interpreter path |
| `aeon.aeonPath` | `""` | Path to AEON project root (for serverless mode) |
| `aeon.verifyOnSave` | `false` | Auto-verify on file save (debounced) |
| `aeon.deepVerify` | `true` | Run all 10 analysis engines |

## Commands

| Command | Keybinding | Description |
|---------|------------|-------------|
| AEON: Verify Current File | `Cmd+Shift+A` | Verify the active file |
| AEON: Verify Selection | — | Verify selected code (also in context menu) |
| AEON: Start Verification Server | — | Start the API server |
| AEON: Stop Verification Server | — | Stop the API server |
| AEON: Show Output | — | Open the AEON output panel |

## Troubleshooting

**"Could not connect to server or run Python"**
- Make sure the AEON API server is running (`python3 -m aeon.api_server --port 8000`)
- Or set `aeon.aeonPath` to the AEON project root for direct Python mode
- Check the AEON output panel (**AEON: Show Output**) for detailed error logs

**Verification is slow**
- Set `aeon.deepVerify` to `false` to skip the full 10-engine suite and use basic analysis only
- Use the API server instead of direct Python mode for faster response times

**No diagnostics appear**
- Verify the file language is set to Python (check the status bar)
- Check the AEON output panel for errors from the server or Python process

## Architecture

The extension is built with TypeScript and split into focused modules:

```
src/
├── extension.ts    — activation, command registration, debounced save
├── verifier.ts     — API client + Python fallback with cancellation
├── diagnostics.ts  — diagnostic creation, result caching
├── statusBar.ts    — status bar lifecycle
├── server.ts       — server process management
├── codeLens.ts     — per-function "Verify" CodeLens
├── hover.ts        — verification result hover tooltips
└── codeActions.ts  — quick-fix code actions
```

## Known Issues

- CodeLens currently triggers a full-file verify rather than single-function verify
- Quick-fix insertions assume 4-space indentation
- No Windows-specific testing yet
