#!/usr/bin/env node
/**
 * AEON Verify — npm wrapper for the AEON formal verification CLI.
 *
 * Requires Python 3.10+ and AEON installed via pip.
 * Usage: npx aeon-verify check file.py --deep-verify
 */

const { execSync, spawnSync } = require('child_process');
const path = require('path');

// Find Python
function findPython() {
    for (const cmd of ['python3', 'python']) {
        try {
            const version = execSync(`${cmd} --version 2>&1`, { encoding: 'utf8' }).trim();
            const match = version.match(/Python 3\.(\d+)/);
            if (match && parseInt(match[1]) >= 10) {
                return cmd;
            }
        } catch {}
    }
    return null;
}

// Check if AEON is installed
function checkAeon(python) {
    try {
        execSync(`${python} -c "import aeon"`, { encoding: 'utf8', stdio: 'pipe' });
        return true;
    } catch {
        return false;
    }
}

const python = findPython();

if (!python) {
    console.error('\x1b[31m[ERROR]\x1b[0m Python 3.10+ not found.');
    console.error('Install Python: https://python.org or run: brew install python@3.11');
    process.exit(1);
}

if (!checkAeon(python)) {
    console.error('\x1b[33m[WARN]\x1b[0m AEON not installed. Installing...');
    try {
        execSync(`${python} -m pip install aeon-lang`, { stdio: 'inherit' });
    } catch {
        console.error('\x1b[31m[ERROR]\x1b[0m Failed to install AEON. Try: pip install aeon-lang');
        process.exit(1);
    }
}

// Forward all arguments to AEON CLI
const args = process.argv.slice(2);
const result = spawnSync(python, ['-m', 'aeon.cli', ...args], {
    stdio: 'inherit',
    env: process.env,
});

process.exit(result.status || 0);
