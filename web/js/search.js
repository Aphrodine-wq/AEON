/* ═══════════════════════════════════════════════════════════
   AEON — Cmd+K Search Modal
   Full-text search across all documentation pages
   ═══════════════════════════════════════════════════════════ */

(function () {
    'use strict';

    /* ── Search Index ─────────────────────────────────────── */
    const SEARCH_DATA = [
        // Getting Started
        { title: 'What is AEON?', section: 'Getting Started', page: 'docs.html', anchor: '#what-is-aeon', keywords: 'introduction overview about formal verification ai native' },
        { title: 'Installation', section: 'Getting Started', page: 'docs.html', anchor: '#installation', keywords: 'install pip brew homebrew docker npm npx scoop windows linux macos setup' },
        { title: 'Your First Verification', section: 'Getting Started', page: 'docs.html', anchor: '#first-verification', keywords: 'quickstart tutorial hello world first example getting started beginner' },
        { title: 'Configuration (.aeonrc.yml)', section: 'Getting Started', page: 'docs.html', anchor: '#configuration', keywords: 'config yaml settings options aeonrc configure setup' },

        // Core Concepts
        { title: 'Three Primitives (pure, task, data)', section: 'Core Concepts', page: 'docs.html', anchor: '#three-primitives', keywords: 'pure task data primitive language basics category theory morphism' },
        { title: 'Contract System', section: 'Core Concepts', page: 'docs.html', anchor: '#contracts', keywords: 'requires ensures precondition postcondition contract z3 smt hoare' },
        { title: 'Effect System', section: 'Core Concepts', page: 'docs.html', anchor: '#effect-system', keywords: 'effects algebraic side effect io database network filesystem' },
        { title: 'Ownership & Borrowing', section: 'Core Concepts', page: 'docs.html', anchor: '#ownership', keywords: 'ownership borrow move rust memory safety use after free dangling' },
        { title: 'Security Labels', section: 'Core Concepts', page: 'docs.html', anchor: '#security-labels', keywords: 'security labels public internal secret top secret lattice information flow' },

        // Verification Engines
        { title: 'Verification Engines Overview', section: 'Engines', page: 'docs.html', anchor: '#engines', keywords: '30+ engines formal methods analysis deep verify' },
        { title: 'Symbolic Execution', section: 'Engines', page: 'docs.html', anchor: '#engine-symbolic', keywords: 'symbolic execution path exploration counterexample z3 king klee' },
        { title: 'Abstract Interpretation', section: 'Engines', page: 'docs.html', anchor: '#engine-abstract', keywords: 'abstract interpretation cousot interval domain galois widening narrowing overflow division' },
        { title: 'Size-Change Termination', section: 'Engines', page: 'docs.html', anchor: '#engine-termination', keywords: 'termination size change ramsey infinite loop halt' },
        { title: 'Hoare Logic / wp-Calculus', section: 'Engines', page: 'docs.html', anchor: '#engine-hoare', keywords: 'hoare logic weakest precondition dijkstra wp calculus invariant' },
        { title: 'Information Flow', section: 'Engines', page: 'docs.html', anchor: '#engine-infoflow', keywords: 'information flow noninterference security type system secret public leak' },
        { title: 'Liquid Types', section: 'Engines', page: 'docs.html', anchor: '#engine-liquid', keywords: 'liquid types refinement type smt predicate abstraction cegar' },
        { title: 'Algebraic Effects', section: 'Engines', page: 'docs.html', anchor: '#engine-effects', keywords: 'algebraic effects row polymorphism plotkin pretnar handler continuation' },
        { title: 'Dependent Types', section: 'Engines', page: 'docs.html', anchor: '#engine-dependent', keywords: 'dependent types curry howard pi type proof proposition martin lof' },
        { title: 'Taint Analysis', section: 'Engines', page: 'docs.html', anchor: '#engine-taint', keywords: 'taint analysis sql injection xss command injection source sink sanitizer' },
        { title: 'Separation Logic', section: 'Engines', page: 'docs.html', anchor: '#engine-separation', keywords: 'separation logic heap memory use after free double free frame rule infer' },
        { title: 'Concurrency Verification', section: 'Engines', page: 'docs.html', anchor: '#engine-concurrency', keywords: 'concurrency race condition deadlock lockset atomicity thread parallel' },
        { title: 'Bounded Model Checking', section: 'Engines', page: 'docs.html', anchor: '#engine-model', keywords: 'model checking state space sat temporal property safety liveness' },
        { title: 'Shape Analysis', section: 'Engines', page: 'docs.html', anchor: '#engine-shape', keywords: 'shape analysis linked list tree graph 3 valued logic canonical abstraction' },
        { title: 'Certified Compilation', section: 'Engines', page: 'docs.html', anchor: '#engine-certified', keywords: 'certified compilation compcert simulation proof compiler pass semantics' },
        { title: 'Category-Theoretic Semantics', section: 'Engines', page: 'docs.html', anchor: '#engine-category', keywords: 'category theory denotational semantics ccc morphism kleisli monad functor' },

        // Multi-Language
        { title: 'Supported Languages (14+)', section: 'Languages', page: 'docs.html', anchor: '#languages', keywords: 'python java javascript typescript go rust c cpp ruby swift kotlin php scala dart language' },
        { title: 'Contract Syntax by Language', section: 'Languages', page: 'docs.html', anchor: '#lang-contracts', keywords: 'contract syntax docstring javadoc jsdoc comment annotation' },
        { title: 'How Adapters Work', section: 'Languages', page: 'docs.html', anchor: '#lang-adapters', keywords: 'adapter parser ast universal custom language plugin' },

        // CLI
        { title: 'CLI Reference', section: 'CLI', page: 'docs.html', anchor: '#cli', keywords: 'cli command line terminal' },
        { title: 'aeon check', section: 'CLI', page: 'docs.html', anchor: '#cli-check', keywords: 'check verify file single command' },
        { title: 'aeon scan', section: 'CLI', page: 'docs.html', anchor: '#cli-scan', keywords: 'scan directory recursive project folder' },
        { title: 'aeon watch', section: 'CLI', page: 'docs.html', anchor: '#cli-watch', keywords: 'watch file change auto verify live reload' },
        { title: 'All CLI Flags', section: 'CLI', page: 'docs.html', anchor: '#cli-flags', keywords: 'flags options deep verify parallel workers format sarif baseline' },

        // Enterprise
        { title: 'Enterprise Guide', section: 'Enterprise', page: 'docs.html', anchor: '#enterprise', keywords: 'enterprise production team organization adoption' },
        { title: 'CI/CD Integration', section: 'Enterprise', page: 'docs.html', anchor: '#ci-cd', keywords: 'ci cd github actions gitlab jenkins pipeline continuous integration deployment' },
        { title: 'SARIF Output', section: 'Enterprise', page: 'docs.html', anchor: '#sarif', keywords: 'sarif static analysis results interchange format github code scanning' },
        { title: 'Baseline / Diff Mode', section: 'Enterprise', page: 'docs.html', anchor: '#baseline', keywords: 'baseline diff incremental adoption new issues only' },
        { title: 'Parallel Scanning', section: 'Enterprise', page: 'docs.html', anchor: '#parallel', keywords: 'parallel multiprocess workers performance speed scaling' },

        // API & Extensions
        { title: 'REST API', section: 'API', page: 'docs.html', anchor: '#api', keywords: 'api rest http server endpoint verify programmatic' },
        { title: 'Python SDK', section: 'API', page: 'docs.html', anchor: '#python-sdk', keywords: 'python sdk library package import verify' },
        { title: 'VS Code Extension', section: 'API', page: 'docs.html', anchor: '#vscode-ext', keywords: 'vscode visual studio code extension plugin editor ide' },

        // Reference
        { title: 'Error Reference', section: 'Reference', page: 'docs.html', anchor: '#error-reference', keywords: 'error code warning message diagnostic troubleshoot' },
        { title: 'Troubleshooting', section: 'Reference', page: 'docs.html', anchor: '#troubleshooting', keywords: 'troubleshooting debug problem issue fix false positive timeout' },
        { title: 'Glossary', section: 'Reference', page: 'docs.html', anchor: '#glossary', keywords: 'glossary term definition formal verification vocabulary' },
        { title: 'FAQ', section: 'Reference', page: 'docs.html', anchor: '#faq', keywords: 'faq frequently asked questions help' },
        { title: 'Academic Papers', section: 'Reference', page: 'docs.html', anchor: '#papers', keywords: 'paper academic research citation reference bibliography' },
        { title: 'Architecture / Compiler Pipeline', section: 'Reference', page: 'docs.html', anchor: '#architecture', keywords: 'architecture compiler pipeline pass prove flatten emit llvm ir' },

        // Advanced
        { title: 'Advanced Configuration', section: 'Advanced', page: 'docs.html', anchor: '#advanced-config', keywords: 'advanced configuration aeonrc yaml environment variable override monorepo suppress' },
        { title: 'Writing Custom Adapters', section: 'Advanced', page: 'docs.html', anchor: '#custom-adapters', keywords: 'custom adapter language plugin write create new extend' },
        { title: 'Migration Guides', section: 'Advanced', page: 'docs.html', anchor: '#migration', keywords: 'migration migrate eslint mypy semgrep codeql infer switch from' },

        // Other pages
        { title: 'Live Demo', section: 'Home', page: 'index.html', anchor: '#demo', keywords: 'demo try live interactive playground' },
        { title: 'Enterprise Use Cases', section: 'Examples', page: 'examples.html', anchor: '', keywords: 'examples enterprise use case finance healthcare ecommerce security infrastructure data' },
        { title: 'Tutorials', section: 'Learn', page: 'tutorials.html', anchor: '', keywords: 'tutorial guide learn how to step by step walkthrough' },
        { title: 'Benchmarks & Comparisons', section: 'Reference', page: 'benchmarks.html', anchor: '', keywords: 'benchmark performance comparison speed semgrep codeql mypy infer' },
        { title: 'Changelog', section: 'Reference', page: 'changelog.html', anchor: '', keywords: 'changelog release notes version history update whats new' },
        { title: 'API Reference', section: 'Reference', page: 'api-reference.html', anchor: '', keywords: 'api reference rest endpoint sdk function class method parameter' },
    ];

    /* ── Fuzzy match ──────────────────────────────────────── */
    function score(query, item) {
        const q = query.toLowerCase();
        const title = item.title.toLowerCase();
        const keywords = item.keywords.toLowerCase();
        const section = item.section.toLowerCase();

        // Exact title match
        if (title === q) return 100;
        // Title starts with query
        if (title.startsWith(q)) return 90;
        // Title contains query
        if (title.includes(q)) return 80;
        // Section contains query
        if (section.includes(q)) return 60;
        // Keywords contain query
        if (keywords.includes(q)) return 50;

        // Word-level matching
        const words = q.split(/\s+/);
        let wordScore = 0;
        for (const w of words) {
            if (title.includes(w)) wordScore += 30;
            else if (keywords.includes(w)) wordScore += 15;
            else if (section.includes(w)) wordScore += 10;
        }
        return wordScore;
    }

    function search(query) {
        if (!query || query.trim().length === 0) return [];
        const results = SEARCH_DATA
            .map(item => ({ ...item, score: score(query, item) }))
            .filter(item => item.score > 0)
            .sort((a, b) => b.score - a.score)
            .slice(0, 12);
        return results;
    }

    /* ── Modal DOM ────────────────────────────────────────── */
    function createModal() {
        const overlay = document.createElement('div');
        overlay.id = 'search-overlay';
        overlay.innerHTML = `
            <div class="search-modal">
                <div class="search-input-wrap">
                    <svg class="search-icon" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
                    </svg>
                    <input type="text" id="search-input" placeholder="Search documentation..." autocomplete="off" spellcheck="false" />
                    <kbd class="search-kbd">ESC</kbd>
                </div>
                <div class="search-results" id="search-results">
                    <div class="search-empty">
                        <p>Type to search across all AEON documentation</p>
                        <div class="search-hints">
                            <span>Try: </span>
                            <button onclick="document.getElementById('search-input').value='symbolic';document.getElementById('search-input').dispatchEvent(new Event('input'))">symbolic</button>
                            <button onclick="document.getElementById('search-input').value='install';document.getElementById('search-input').dispatchEvent(new Event('input'))">install</button>
                            <button onclick="document.getElementById('search-input').value='taint';document.getElementById('search-input').dispatchEvent(new Event('input'))">taint</button>
                            <button onclick="document.getElementById('search-input').value='ci/cd';document.getElementById('search-input').dispatchEvent(new Event('input'))">ci/cd</button>
                        </div>
                    </div>
                </div>
                <div class="search-footer">
                    <span><kbd>&uarr;</kbd><kbd>&darr;</kbd> Navigate</span>
                    <span><kbd>Enter</kbd> Open</span>
                    <span><kbd>Esc</kbd> Close</span>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);
        return overlay;
    }

    /* ── Render results ───────────────────────────────────── */
    function renderResults(results, container) {
        if (results.length === 0) {
            container.innerHTML = '<div class="search-no-results">No results found</div>';
            return;
        }

        let currentSection = '';
        let html = '';
        for (let i = 0; i < results.length; i++) {
            const r = results[i];
            if (r.section !== currentSection) {
                currentSection = r.section;
                html += `<div class="search-section-label">${currentSection}</div>`;
            }
            const href = r.page + r.anchor;
            html += `<a class="search-result-item${i === 0 ? ' active' : ''}" href="${href}" data-index="${i}">
                <span class="search-result-title">${r.title}</span>
                <span class="search-result-page">${r.page.replace('.html', '')}</span>
            </a>`;
        }
        container.innerHTML = html;
    }

    /* ── Keyboard navigation ──────────────────────────────── */
    let activeIndex = 0;

    function setActive(container, index) {
        const items = container.querySelectorAll('.search-result-item');
        if (items.length === 0) return;
        items.forEach(el => el.classList.remove('active'));
        activeIndex = Math.max(0, Math.min(index, items.length - 1));
        items[activeIndex].classList.add('active');
        items[activeIndex].scrollIntoView({ block: 'nearest' });
    }

    /* ── Init ─────────────────────────────────────────────── */
    let overlay = null;

    function openSearch() {
        if (!overlay) overlay = createModal();
        overlay.classList.add('open');
        const input = document.getElementById('search-input');
        input.value = '';
        input.focus();
        activeIndex = 0;
        document.getElementById('search-results').innerHTML =
            `<div class="search-empty">
                <p>Type to search across all AEON documentation</p>
                <div class="search-hints">
                    <span>Try: </span>
                    <button onclick="document.getElementById('search-input').value='symbolic';document.getElementById('search-input').dispatchEvent(new Event('input'))">symbolic</button>
                    <button onclick="document.getElementById('search-input').value='install';document.getElementById('search-input').dispatchEvent(new Event('input'))">install</button>
                    <button onclick="document.getElementById('search-input').value='taint';document.getElementById('search-input').dispatchEvent(new Event('input'))">taint</button>
                    <button onclick="document.getElementById('search-input').value='ci/cd';document.getElementById('search-input').dispatchEvent(new Event('input'))">ci/cd</button>
                </div>
            </div>`;
        document.body.style.overflow = 'hidden';
    }

    function closeSearch() {
        if (overlay) {
            overlay.classList.remove('open');
            document.body.style.overflow = '';
        }
    }

    // Keyboard shortcut: Cmd+K / Ctrl+K
    document.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
            e.preventDefault();
            if (overlay && overlay.classList.contains('open')) {
                closeSearch();
            } else {
                openSearch();
            }
        }
        if (e.key === 'Escape') closeSearch();
    });

    // Delegated events
    document.addEventListener('click', (e) => {
        if (e.target.id === 'search-overlay') closeSearch();
        if (e.target.closest('.search-trigger')) { e.preventDefault(); openSearch(); }
    });

    document.addEventListener('input', (e) => {
        if (e.target.id === 'search-input') {
            const results = search(e.target.value);
            const container = document.getElementById('search-results');
            renderResults(results, container);
            activeIndex = 0;
        }
    });

    document.addEventListener('keydown', (e) => {
        if (!overlay || !overlay.classList.contains('open')) return;
        const container = document.getElementById('search-results');
        const items = container.querySelectorAll('.search-result-item');
        if (items.length === 0) return;

        if (e.key === 'ArrowDown') {
            e.preventDefault();
            setActive(container, activeIndex + 1);
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            setActive(container, activeIndex - 1);
        } else if (e.key === 'Enter') {
            e.preventDefault();
            const active = container.querySelector('.search-result-item.active');
            if (active) window.location.href = active.getAttribute('href');
        }
    });

    // Expose for nav button
    window.openAeonSearch = openSearch;
})();
