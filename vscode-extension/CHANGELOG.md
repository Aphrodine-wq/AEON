# Changelog

## [0.2.0] — 2026-02-22

### Added
- **TypeScript migration** — full rewrite from JavaScript to TypeScript with modular architecture
- **Syntax highlighting** for `.aeon` files (keywords, types, contracts, strings, numbers, comments)
- **CodeLens** — "Verify" lens appears above every function definition
- **Hover provider** — hover over verified functions to see results inline
- **Code actions** — quick-fix suggestions (e.g., add `requires` guard for division by zero)
- **Output channel** — AEON logs visible in the Output panel
- **Progress notifications** — cancellable progress bar during verification
- **Context menu** — "Verify Selection" available in editor right-click menu
- **Debounced verify-on-save** — 500ms debounce prevents spamming the server
- **Show Output command** — quickly open the AEON output panel

### Changed
- **Keybinding** — changed from `Cmd+Shift+V` (conflicted with paste) to `Cmd+Shift+A`
- **Status bar** — error background color on failures, auto-resets after 8 seconds
- **Error messages** — more specific diagnostics with column info and engine attribution

### Fixed
- Keybinding conflict with VS Code's built-in paste command

## [0.1.0] — Initial Release

### Added
- Verify Python files via AEON API server or direct Python execution
- Inline diagnostics (errors and warnings)
- Status bar indicator
- Verify-on-save option
- Server start/stop commands
