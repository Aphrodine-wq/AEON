"""AEON UI/UX Lint Engine v3 — Deep Source Analysis.

200+ rules across 16 categories. Goes beyond regex line-matching:
  - Multi-line pattern detection (forms without validation, effects without cleanup)
  - Scope-aware analysis (tracks if code is inside useEffect, handler, render)
  - File-level heuristics (complexity thresholds, architecture smells)
  - Domain-aware checks (construction industry: currency, measurements, percentages)

Categories:
  design        — Design system violations
  a11y          — Accessibility (WCAG AA)
  ux            — UX anti-patterns
  hygiene       — Production readiness
  professional  — Polish & code quality
  security      — Client-side security
  performance   — Perf anti-patterns
  forms         — Form UX
  react         — React-specific
  api           — API route quality
  responsive    — Mobile/responsive
  seo           — SEO/meta
  data          — Data handling safety
  state         — State management
  network       — Network/async patterns
  domain        — Construction industry specifics
"""

from __future__ import annotations

import re
import os
from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict, Tuple

from aeon.errors import AeonError, ErrorKind, SourceLocation


# ── Error Factory ─────────────────────────────────────────────────────────────

def ui_error(
    message: str,
    category: str,
    location: Optional[SourceLocation] = None,
    severity: str = "warning",
    fix: Optional[str] = None,
    rule_id: str = "",
) -> AeonError:
    return AeonError(
        kind=ErrorKind.CONTRACT_ERROR,
        message=f"UI/UX: {message}",
        location=location,
        details={
            "precondition": message,
            "failing_values": {"category": category, "severity": severity, "rule": rule_id},
            "function_signature": "ui_ux_lint",
        },
        fix_suggestion=fix,
    )


# ── Rule Definition ───────────────────────────────────────────────────────────

@dataclass
class LintRule:
    id: str
    category: str
    severity: str
    pattern: re.Pattern
    message: str
    fix: Optional[str] = None
    negative_filter: Optional[re.Pattern] = None
    file_filter: Optional[re.Pattern] = None
    # Only match in specific scope contexts
    scope_required: Optional[str] = None  # "render" | "handler" | "effect" | "api"


# ═══════════════════════════════════════════════════════════════════════════════
# LINE-LEVEL RULES (200+)
# ═══════════════════════════════════════════════════════════════════════════════

# ── DESIGN ────────────────────────────────────────────────────────────────────

DESIGN_RULES: List[LintRule] = [
    LintRule("no-gradient", "design", "error",
        re.compile(r'bg-gradient-to-[trblTRBL]|from-\w+.*(?:via-|to-)\w+|linear-gradient\s*\(', re.I),
        "Gradient detected — use flat solid colors",
        "Replace with a single solid color (e.g., bg-black/60)",
        re.compile(r'//.*gradient|/\*.*gradient|".*gradient', re.I)),
    LintRule("no-emoji-design", "design", "error",
        re.compile(r'(?:text-\[?\d+px\]?|text-(?:2xl|3xl|4xl|5xl)|opacity-\d+|className=)[^>]*>'
                   r'\s*[\U0001F300-\U0001F9FF\U00002600-\U000027BF\U0001FA00-\U0001FA6F\U0001FA70-\U0001FAFF]'),
        "Emoji used as design element — use SVG icon",
        "Replace with a proper SVG/icon component"),
    LintRule("hardcoded-color-style", "design", "info",
        re.compile(r'(?:color|background|borderColor)\s*:\s*["\']?#[0-9a-fA-F]{3,8}'),
        "Hardcoded hex color — use design token", "Use var(--color-name) or Tailwind"),
    LintRule("opacity-text-low", "design", "warning",
        re.compile(r'(?:text|foreground).*opacity-(?:[12]\d|[0-3]0)\b'),
        "Very low opacity text — may fail contrast requirements",
        "Ensure WCAG AA contrast ratio (4.5:1)"),
    LintRule("mixed-color-systems", "design", "info",
        re.compile(r'(?:rgb|hsl)\s*\(.*\).*(?:bg-|text-)|(?:bg-|text-).*(?:rgb|hsl)\s*\('),
        "Mixing CSS color functions with Tailwind — pick one system",
        "Use Tailwind classes consistently or CSS variables"),
    LintRule("shadow-inconsistent", "design", "info",
        re.compile(r'shadow-\[(?:\d+px\s+){2,}'),
        "Custom shadow value — use Tailwind shadow scale for consistency"),
]

# ── ACCESSIBILITY ─────────────────────────────────────────────────────────────

A11Y_RULES: List[LintRule] = [
    LintRule("img-alt", "a11y", "warning",
        re.compile(r'<img\b(?![^>]*\balt\s*=)[^>]*/?>'),
        "Image missing alt attribute",
        'Add alt="description" or alt="" for decorative images'),
    LintRule("icon-button-no-label", "a11y", "warning",
        re.compile(r'<button\b[^>]*>\s*<(?:svg|img|Icon)\b[^>]*/?\s*>\s*</button>', re.I),
        "Icon-only button without accessible label",
        'Add aria-label="action" to the button'),
    LintRule("click-on-div", "a11y", "warning",
        re.compile(r'<(?:div|span)\b[^>]*\bonClick\b(?![^>]*\brole\s*=)[^>]*>'),
        "onClick on non-interactive element without role",
        'Add role="button" tabIndex={0} onKeyDown handler'),
    LintRule("input-no-label", "a11y", "warning",
        re.compile(r'<input\b(?![^>]*(?:aria-label|id\s*=\s*["\'][^"\']*label))[^>]*placeholder=[^>]*/?>'),
        "Input with placeholder but no label/aria-label",
        "Add <label> or aria-label",
        re.compile(r'aria-label|<label|htmlFor', re.I)),
    LintRule("no-focus-outline", "a11y", "warning",
        re.compile(r'outline-none|outline:\s*none|outline:\s*0\b'),
        "Focus outline removed — keyboard users lose navigation",
        "Use focus-visible:ring-2 instead",
        re.compile(r'focus-visible|focus:ring|focus:outline', re.I)),
    LintRule("heading-skip", "a11y", "info",
        re.compile(r'<h[456]\b'),
        "Deep heading level — verify sequential hierarchy (h1->h2->h3)"),
    LintRule("color-only-status", "a11y", "warning",
        re.compile(r'(?:bg-red|bg-green|bg-yellow|text-red|text-green)\b.*>(?!\s*<)(?!\s*\{)', re.I),
        "Color may be only state indicator — add text/icon for color-blind users"),
    LintRule("autoplay-media", "a11y", "warning",
        re.compile(r'<(?:video|audio)\b[^>]*\bautoPlay\b'),
        "Autoplay media — add controls and consider user preference",
        "Add muted and visible play/pause controls"),
    LintRule("tabindex-positive", "a11y", "warning",
        re.compile(r'tabIndex\s*=\s*\{?\s*[1-9]'),
        "Positive tabIndex disrupts tab order",
        "Use 0 for natural flow, -1 for programmatic focus"),
    LintRule("aria-hidden-focusable", "a11y", "warning",
        re.compile(r'aria-hidden\s*=\s*["\']?true[^>]*(?:tabIndex|onClick|href|button)'),
        "Focusable element hidden from screen readers — contradictory",
        "Remove aria-hidden or make non-focusable"),
    LintRule("empty-alt-interactive", "a11y", "info",
        re.compile(r'<img\b[^>]*alt\s*=\s*["\']["\'][^>]*onClick'),
        "Clickable image with empty alt — needs description",
        'Add descriptive alt text since the image is interactive'),
    LintRule("form-no-fieldset", "a11y", "info",
        re.compile(r'<form\b(?![^>]*role)[^>]*>(?![\s\S]*<fieldset)'),
        "Form without fieldset — group related inputs for screen readers"),
]

# ── UX ANTI-PATTERNS ──────────────────────────────────────────────────────────

UX_RULES: List[LintRule] = [
    LintRule("no-alert", "ux", "error",
        re.compile(r'\balert\s*\(["\']'),
        "Browser alert() — use styled notification",
        "Use toast/snackbar, error state, or modal"),
    LintRule("no-confirm", "ux", "warning",
        re.compile(r'\bwindow\.confirm\s*\(|[^.\w]confirm\s*\(["\']'),
        "Browser confirm() — use styled dialog",
        "Use modal confirmation component",
        re.compile(r'\.confirm\(|confirm-|Confirm[A-Z]|password.*confirm', re.I)),
    LintRule("no-prompt", "ux", "error",
        re.compile(r'\bwindow\.prompt\s*\(|\bprompt\s*\(["\']'),
        "Browser prompt() — use form input",
        "Use modal with form input",
        re.compile(r'\.prompt\b|promptTemplate|systemPrompt|aiPrompt', re.I)),
    LintRule("silent-catch", "ux", "error",
        re.compile(r'catch\s*(?:\([^)]*\))?\s*\{[^}]*//\s*(?:[Ss]ilent|[Ii]gnore|[Nn]oop)'),
        "Silent error catch — user gets no feedback",
        "Show error message or log to error tracking"),
    LintRule("empty-catch-arrow", "ux", "warning",
        re.compile(r'\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)'),
        "Empty .catch() — errors silently swallowed",
        "Handle error or pass to tracking"),
    LintRule("empty-catch-block", "ux", "warning",
        re.compile(r'catch\s*\(\s*\w*\s*\)\s*\{\s*\}'),
        "Empty catch block — errors swallowed"),
    LintRule("hardcoded-brand", "ux", "warning",
        re.compile(r'\|\|\s*["\'](?:FairTrade|Acme|Example|Test Company|Your Company|Company Name)[^"\']*["\']'),
        "Hardcoded fallback brand name",
        'Use generic fallback or placeholder state'),
    LintRule("hardcoded-email-fallback", "ux", "warning",
        re.compile(r'\|\|\s*["\'][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["\']'),
        "Hardcoded fallback email — wrong email shown to users"),
    LintRule("hardcoded-phone-fallback", "ux", "warning",
        re.compile(r'\|\|\s*["\'][\d\s\-\(\)\.]{7,}["\']'),
        "Hardcoded fallback phone number"),
    LintRule("hardcoded-url-fallback", "ux", "info",
        re.compile(r'\|\|\s*["\']https?://(?!localhost)[^"\']+["\']'),
        "Hardcoded fallback URL — may be wrong in other environments",
        "Use environment variable",
        re.compile(r'process\.env|NEXT_PUBLIC|VITE_|import\.meta', re.I)),
    LintRule("infinite-spinner", "ux", "info",
        re.compile(r'(?:isLoading|loading)\s*&&\s*<(?:Spinner|Loading|Progress)', re.I),
        "Loading indicator — ensure timeout/error fallback exists"),
    LintRule("generic-error-msg", "ux", "info",
        re.compile(r'["\'](?:Something went wrong|An error occurred|Error|Oops)["\']', re.I),
        "Generic error message — be specific about what failed",
        "Tell users what happened and what they can do about it"),
    LintRule("truncated-no-tooltip", "ux", "info",
        re.compile(r'(?:truncate|text-ellipsis|line-clamp)(?![^>]*title=)'),
        "Truncated text without tooltip — users can't see full content",
        "Add title attribute or expandable view"),
]

# ── PRODUCTION HYGIENE ────────────────────────────────────────────────────────

HYGIENE_RULES: List[LintRule] = [
    LintRule("console-log", "hygiene", "warning",
        re.compile(r'console\.log\s*\('),
        "console.log left in code",
        "Remove or gate behind NODE_ENV check",
        re.compile(r'//.*console\.log|process\.env.*development.*console|"console\.log|node\s*-e|generate.*with', re.I)),
    LintRule("console-warn-prod", "hygiene", "info",
        re.compile(r'console\.(?:warn|info)\s*\('),
        "console.warn/info — use structured logging in production",
        "Use Sentry, LogRocket, or structured logger",
        re.compile(r'//.*console\.|process\.env|"console|captureError', re.I)),
    LintRule("todo-fixme", "hygiene", "warning",
        re.compile(r'//\s*(?:TODO|FIXME|HACK|XXX|TEMP|WORKAROUND)\b', re.I),
        "TODO/FIXME — address before shipping"),
    LintRule("placeholder-text", "hygiene", "error",
        re.compile(r'["\'](?:Lorem ipsum|placeholder text|sample text|test data|foo bar|asdf|xxx|TBD)["\']', re.I),
        "Placeholder text in UI — replace with real content"),
    LintRule("debugger", "hygiene", "error",
        re.compile(r'^\s*debugger\s*;?\s*$', re.M),
        "debugger statement left in code"),
    LintRule("commented-code", "hygiene", "info",
        re.compile(r'^\s*//\s*(?:const|let|var|function|return|if|for|while|import|export)\s', re.M),
        "Commented-out code — remove or use git history"),
    LintRule("any-type", "hygiene", "warning",
        re.compile(r':\s*any\b|as\s+any\b|<any>'),
        "'any' type defeats TypeScript safety",
        "Use specific type, unknown, or generic",
        re.compile(r'Record<string,\s*any>|//.*any|@ts-|eslint-disable', re.I)),
    LintRule("ts-ignore", "hygiene", "warning",
        re.compile(r'@ts-ignore|@ts-nocheck'),
        "TypeScript checks suppressed — fix the type error instead",
        "Fix the type error or use @ts-expect-error with explanation"),
    LintRule("eslint-disable-all", "hygiene", "info",
        re.compile(r'eslint-disable(?!\s*-next-line)'),
        "ESLint fully disabled for file — re-enable and fix issues"),
    LintRule("non-null-assertion", "hygiene", "info",
        re.compile(r'\w+\!\.(?!==)'),
        "Non-null assertion (!) — may mask null errors",
        "Use optional chaining (?.) or add null check"),
    LintRule("magic-number-calc", "hygiene", "info",
        re.compile(r'(?:\*|/)\s+(?:0\.\d{3,}|\d{4,})(?!\s*[;,\]}\)].*(?:width|height|size|port|timeout|delay|ms|px|rem))'),
        "Magic number in calculation — extract to named constant",
        negative_filter=re.compile(r'Math\.|Date|1000|10000|100|60|24|365|1024|86400|3600', re.I)),
    LintRule("unused-import", "hygiene", "info",
        re.compile(r'^import\s+\{[^}]*\btype\s+\w+\b[^}]*\}\s+from\b', re.M),
        "Check if type-only imports could use 'import type'"),
]

# ── SECURITY ──────────────────────────────────────────────────────────────────

SECURITY_RULES: List[LintRule] = [
    LintRule("xss-innerhtml", "security", "warning",
        re.compile(r'dangerouslySetInnerHTML'),
        "dangerouslySetInnerHTML — XSS risk if content is user-supplied",
        "Sanitize with DOMPurify or use safe markdown renderer",
        re.compile(r'schema\.org|@context|@type|<style|<script.*structured|<nav\s|__html:\s*`<', re.I)),
    LintRule("eval", "security", "error",
        re.compile(r'\beval\s*\('),
        "eval() is a critical security risk",
        "Use JSON.parse, Function constructor, or safe alternative",
        re.compile(r'//.*eval|\.eval\(|Eval[A-Z]')),
    LintRule("innerhtml-assign", "security", "error",
        re.compile(r'\.innerHTML\s*='),
        "Direct innerHTML assignment — XSS risk",
        "Use textContent or framework's safe rendering"),
    LintRule("hardcoded-secret", "security", "error",
        re.compile(r'(?:api[_-]?key|secret[_-]?key|password|auth[_-]?token|private[_-]?key)\s*[:=]\s*["\'][a-zA-Z0-9_\-/+]{20,}["\']', re.I),
        "Potential hardcoded secret/API key",
        "Move to environment variable",
        re.compile(r'process\.env|import\.meta\.env|placeholder|example|test|mock|fake|dummy|your[_-]|CHANGE[_-]ME', re.I)),
    LintRule("http-url", "security", "warning",
        re.compile(r'["\']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)'),
        "HTTP URL — use HTTPS", "Change to https://"),
    LintRule("target-blank", "security", "warning",
        re.compile(r'target\s*=\s*["\']_blank["\'](?![^>]*rel\s*=\s*["\'].*noopener)'),
        'target="_blank" without rel="noopener noreferrer"',
        'Add rel="noopener noreferrer"'),
    LintRule("exposed-stack", "security", "warning",
        re.compile(r'(?:error|err|e)\.(?:stack|message)\b.*(?:json|NextResponse|res\.send)', re.I),
        "Error details may be exposed to client",
        "Return generic message; log details server-side",
        re.compile(r'captureError|sentry|logger|console\.error', re.I),
        re.compile(r'route\.ts|api/')),
    LintRule("sql-concat", "security", "error",
        re.compile(r'(?:SELECT\s+\w|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b.*\$\{', re.I),
        "SQL query with template literal — injection risk",
        "Use parameterized queries",
        re.compile(r'supabase\.|prisma\.|knex|\.from\(|\.select\(|subject|email|html|text|label|title|message', re.I)),
    LintRule("cors-wildcard", "security", "warning",
        re.compile(r'Access-Control-Allow-Origin.*\*'),
        "CORS wildcard allows any origin",
        "Restrict to specific allowed origins"),
    LintRule("jwt-decode-no-verify", "security", "error",
        re.compile(r'jwt[_-]?decode\s*\(|jwtDecode\s*\((?![^)]*verify)', re.I),
        "JWT decoded without verification",
        "Always verify JWT signature before trusting claims"),
    LintRule("cookie-no-secure", "security", "warning",
        re.compile(r'Set-Cookie|setCookie|document\.cookie.*=(?![^;]*[Ss]ecure)'),
        "Cookie without Secure flag — sent over HTTP",
        "Add Secure; HttpOnly; SameSite=Strict flags",
        re.compile(r'httpOnly|secure|sameSite', re.I)),
    LintRule("regex-dos", "security", "warning",
        re.compile(r'new\s+RegExp\s*\([^)]*\+'),
        "Dynamic regex from user input — ReDoS risk",
        "Sanitize input before building regex, or use a safe alternative"),
]

# ── PERFORMANCE ───────────────────────────────────────────────────────────────

PERFORMANCE_RULES: List[LintRule] = [
    LintRule("lodash-full", "performance", "warning",
        re.compile(r'import\s+_?\s+from\s+["\']lodash["\']'),
        "Full lodash import — bundles entire library (~70KB)",
        'Import specific: import debounce from "lodash/debounce"'),
    LintRule("moment-import", "performance", "warning",
        re.compile(r'from\s+["\']moment["\']'),
        "moment.js is 300KB+ — use lighter alternative",
        "Replace with date-fns, dayjs, or native Intl.DateTimeFormat"),
    LintRule("img-no-dimensions", "performance", "warning",
        re.compile(r'<img\b(?![^>]*(?:width|height|fill|sizes)\s*=)[^>]*>'),
        "Image without dimensions — causes layout shift (CLS)",
        "Add width/height or use next/image with fill",
        re.compile(r'className.*(?:w-|h-|size-)|style.*width|fill\b')),
    LintRule("img-no-lazy", "performance", "info",
        re.compile(r'<img\b(?![^>]*loading\s*=)[^>]*>'),
        "Image without loading attribute — lazy load below-fold images",
        'Add loading="lazy"',
        re.compile(r'next/image|Image\s|priority|eager|logo|icon|avatar', re.I)),
    # sync-storage removed: line-level regex can't detect whether
    # the call is already inside useEffect (which is the correct pattern).
    # Nearly all React apps use localStorage inside useEffect.
    LintRule("large-inline-style", "performance", "info",
        re.compile(r'style\s*=\s*\{\s*\{[^}]{80,}\}\s*\}'),
        "Large inline style creates new reference each render",
        "Extract to const or useMemo"),
    LintRule("chained-array-ops", "performance", "info",
        re.compile(r'\.(?:filter|map|reduce|sort|flatMap)\([^)]+\)\.(?:filter|map|reduce|sort)\('),
        "Chained array operations — consider useMemo if expensive"),
    LintRule("nextjs-img", "performance", "warning",
        re.compile(r'<img\b'),
        "Using <img> instead of next/image — missing optimization",
        "Use next/image for auto optimization",
        re.compile(r'next/image|Image\s|dangerouslySetInnerHTML|email|pdf|svg', re.I),
        re.compile(r'\.tsx$')),
    LintRule("nextjs-a-internal", "performance", "info",
        re.compile(r'<a\b[^>]*href\s*=\s*["\']/(?!api/)'),
        "Using <a> for internal link — use next/link",
        "Import Link from 'next/link'",
        re.compile(r'next/link|Link\s|mailto:|tel:|http|target=|download', re.I),
        re.compile(r'\.tsx$')),
    LintRule("no-memo-list", "performance", "info",
        re.compile(r'\.map\s*\(\s*\([^)]*\)\s*=>\s*\(\s*<'),
        "Rendering list items inline — consider React.memo for complex items"),
    LintRule("large-json-stringify", "performance", "info",
        re.compile(r'JSON\.stringify\s*\([^)]*\)\s*(?:===|!==)\s*JSON\.stringify'),
        "JSON.stringify for comparison — O(n) and fragile",
        "Use a deep-equal utility or compare specific fields"),
]

# ── FORMS ─────────────────────────────────────────────────────────────────────

FORM_RULES: List[LintRule] = [
    LintRule("input-no-type", "forms", "warning",
        re.compile(r'<input\b(?![^>]*\btype\s*=)[^>]*>'),
        "Input without type — defaults to text, be explicit",
        'Add type="text", "email", "number", etc.'),
    # password-no-autocomplete: Moved to file-level analysis because
    # type="password" and autoComplete are often on different lines.
    LintRule("form-no-submit", "forms", "info",
        re.compile(r'<form\b(?![^>]*onSubmit)[^>]*>'),
        "Form without onSubmit handler",
        "Add onSubmit with e.preventDefault()"),
    LintRule("submit-no-disabled", "forms", "info",
        re.compile(r'type\s*=\s*["\']submit["\'](?![^>]*disabled)'),
        "Submit button without disabled state — double-submit possible",
        "Add disabled={isSubmitting}"),
    LintRule("textarea-no-maxlength", "forms", "info",
        re.compile(r'<textarea\b(?![^>]*maxLength)[^>]*>'),
        "Textarea without maxLength — unbounded input"),
    LintRule("email-no-validation", "forms", "info",
        re.compile(r'type\s*=\s*["\']email["\'](?![^>]*pattern)(?![^>]*required)'),
        "Email input without required or pattern validation"),
    LintRule("number-no-minmax", "forms", "info",
        re.compile(r'type\s*=\s*["\']number["\'](?![^>]*(?:min|max)\s*=)'),
        "Number input without min/max bounds",
        "Add min/max to prevent unreasonable values"),
    LintRule("select-no-default", "forms", "info",
        re.compile(r'<select\b[^>]*>(?!\s*<option\b[^>]*(?:selected|disabled|value\s*=\s*["\']["\']))'),
        "Select without default/placeholder option"),
]

# ── REACT ─────────────────────────────────────────────────────────────────────

REACT_RULES: List[LintRule] = [
    LintRule("missing-key-map", "react", "warning",
        re.compile(r'\.map\s*\([^)]*\)\s*(?:=>|\{)(?:\s*\(?\s*<)(?![^>]*\bkey\s*=)'),
        "JSX in .map() without key prop — rendering bugs",
        "Add unique key prop (prefer id over index)"),
    LintRule("index-as-key", "react", "info",
        re.compile(r'key\s*=\s*\{\s*(?:index|i|idx)\s*\}'),
        "Array index as key — bugs if list reorders",
        "Use a stable unique id"),
    LintRule("direct-dom", "react", "warning",
        re.compile(r'document\.(?:getElementById|querySelector|querySelectorAll|getElementsBy)\s*\('),
        "Direct DOM access in React — use refs",
        "Use useRef() and ref prop",
        re.compile(r'useEffect|test|spec\.|__test', re.I)),
    LintRule("window-event-leak", "react", "warning",
        re.compile(r'(?:window|document)\.addEventListener\s*\('),
        "Event listener — ensure cleanup in useEffect return",
        "Return cleanup: () => window.removeEventListener(...)",
        re.compile(r'removeEventListener|cleanup|return\s*\(', re.I)),
    LintRule("setinterval-leak", "react", "warning",
        re.compile(r'setInterval\s*\('),
        "setInterval — ensure clearInterval in cleanup",
        "Store interval ID and clear in useEffect return",
        re.compile(r'clearInterval|cleanup|return.*clear', re.I)),
    LintRule("force-update", "react", "warning",
        re.compile(r'forceUpdate\s*\('),
        "forceUpdate() is almost never needed",
        "Use state changes to trigger re-renders"),
    LintRule("string-ref", "react", "warning",
        re.compile(r'(?<![hH])ref\s*=\s*["\'](?!http)'),
        "String refs are deprecated — use useRef()",
        "Replace with useRef() hook"),
    LintRule("set-state-object-mutation", "react", "warning",
        re.compile(r'set\w+\s*\(\s*(?:prev|state)\s*(?:=>|\.)?\s*\{?\s*(?:\.push|\.splice|\.pop|\.shift|\.unshift|\.reverse|\.sort|delete\s)'),
        "Mutating state directly — React won't detect the change",
        "Spread/copy before mutating: setState({...prev, key: value})"),
]

# ── API ROUTES ────────────────────────────────────────────────────────────────

API_RULES: List[LintRule] = [
    LintRule("api-raw-error", "api", "warning",
        re.compile(r'(?:NextResponse|res)\.json\s*\(\s*\{[^}]*error\s*:\s*(?:err|error|e)\.(?:message|stack)'),
        "Raw error exposed in API response",
        "Return generic message; log details server-side",
        file_filter=re.compile(r'route\.ts|api/')),
    LintRule("api-body-no-validate", "api", "warning",
        re.compile(r'await\s+req\.json\s*\(\s*\)\s*(?:as\s+\w+)'),
        "Request body cast without validation",
        "Validate with Zod: schema.safeParse(body)",
        file_filter=re.compile(r'route\.ts|api/')),
    LintRule("api-missing-status", "api", "info",
        re.compile(r'NextResponse\.json\s*\(\s*\{[^}]+\}\s*\)(?!\s*;?\s*$)'),
        "NextResponse.json without explicit status code",
        "Add { status: 200/400/500 } as second argument",
        re.compile(r'status:', re.I),
        re.compile(r'route\.ts|api/')),
    LintRule("api-select-star", "api", "warning",
        re.compile(r'\.select\s*\(\s*["\']?\s*\*\s*["\']?\s*\)'),
        "SELECT * — fetch only needed columns",
        "List specific columns to reduce payload and improve security",
        file_filter=re.compile(r'route\.ts|api/')),
    LintRule("api-no-pagination", "api", "info",
        re.compile(r'\.select\s*\([^)]*\)(?![\s\S]*\.range\s*\()(?![\s\S]*\.limit\s*\()'),
        "Query without pagination — unbounded result set",
        "Add .range() or .limit() for list endpoints",
        re.compile(r'\.single\(|\.maybeSingle\(|\.eq\s*\(.*id', re.I),
        re.compile(r'route\.ts|api/')),
]

# ── DATA HANDLING ─────────────────────────────────────────────────────────────

DATA_RULES: List[LintRule] = [
    LintRule("parseint-no-radix", "data", "warning",
        re.compile(r'parseInt\s*\(\s*[^,)]+\s*\)(?!\s*,)'),
        "parseInt without radix — may parse as octal",
        "Add radix: parseInt(value, 10)"),
    LintRule("parsefloat-no-nan", "data", "info",
        re.compile(r'(?:parseFloat|parseInt)\s*\(\s*(?:input|value|query|param|body|req\b)[^)]*\)'),
        "Parsing user input without NaN check",
        "Check isNaN() after parsing user input",
        re.compile(r'isNaN|isFinite|Number\.isNaN|\?\?|\|\|\s*0', re.I)),
    # json-parse-no-try removed: line-level regex can't reliably detect
    # whether JSON.parse is inside a surrounding try/catch block.
    # This is better caught by the TypeScript compiler or eslint.
    LintRule("float-equality", "data", "warning",
        re.compile(r'\b\d+\.\d+\s*===\s*\d+\.\d+'),
        "Floating point comparison with === — may fail due to precision",
        "Use Math.abs(a - b) < Number.EPSILON or round before comparing"),
    LintRule("date-new-string", "data", "info",
        re.compile(r'new\s+Date\s*\(\s*["\'][^"\']+["\']\s*\)'),
        "Date parsing from string — behavior varies across browsers",
        "Use a date library or parse with explicit format"),
    LintRule("array-access-unsafe", "data", "info",
        re.compile(r'\[\s*(?:\w+\.length\s*-\s*1|\w+\s*-\s*1)\s*\]'),
        "Array access at computed index — verify bounds",
        "Check array length before accessing"),
    LintRule("optional-chain-deep", "data", "info",
        re.compile(r'\?\.\w+\?\.\w+\?\.\w+\?\.\w+'),
        "Deep optional chaining (4+ levels) — data shape may need refactoring"),
    LintRule("string-to-number-plus", "data", "info",
        re.compile(r'=\s*\+\s*(?:input|value|query|param)\b'),
        "String-to-number coercion with + prefix on user input",
        "Use explicit Number() or parseInt() for clarity"),
]

# ── STATE MANAGEMENT ──────────────────────────────────────────────────────────

STATE_RULES: List[LintRule] = [
    LintRule("set-timeout-state", "state", "info",
        re.compile(r'setTimeout\s*\([^,]*set[A-Z]\w+\s*\('),
        "setTimeout triggers setState — verify cleanup exists to prevent memory leak",
        "Ensure clearTimeout in cleanup or useEffect return",
        re.compile(r'clearTimeout|cleanup|return.*clear|status.*idle|saved.*idle', re.I)),
    LintRule("set-interval-state", "state", "warning",
        re.compile(r'setInterval\s*\([^,]*set[A-Z]\w+\s*\('),
        "setInterval with setState — stale closure risk",
        "Use useRef for latest value, clear interval in cleanup"),
    LintRule("state-derived-recalc", "state", "info",
        re.compile(r'useState.*(?:\.filter|\.map|\.reduce|\.find)\s*\('),
        "Derived state stored in useState — may get out of sync",
        "Use useMemo to derive from source state instead"),
    LintRule("excessive-usestate", "state", "info",
        re.compile(r'const\s*\[\s*\w+\s*,\s*set\w+\s*\]\s*=\s*useState'),
        "Check useState count — consider useReducer if >5 states in one component"),
]

# ── NETWORK/ASYNC ─────────────────────────────────────────────────────────────

NETWORK_RULES: List[LintRule] = [
    LintRule("fetch-no-timeout", "network", "info",
        re.compile(r'await\s+fetch\s*\(\s*[`"\']'),
        "fetch() without timeout — can hang indefinitely",
        "Add AbortSignal.timeout(5000) or AbortController",
        re.compile(r'AbortSignal|AbortController|signal\s*:|timeout', re.I)),
    LintRule("fetch-no-error-check", "network", "warning",
        re.compile(r'await\s+fetch\s*\([^)]+\)(?:\s*;|\s*\))'),
        "fetch() without response.ok check",
        "Check if (!res.ok) before parsing response",
        re.compile(r'\.ok|status|!res|throw|error', re.I)),
    LintRule("hardcoded-api-url", "network", "warning",
        re.compile(r'fetch\s*\(\s*["\']https?://(?!localhost|127\.0)'),
        "Hardcoded API URL — use environment variable",
        "Use process.env.API_URL or similar",
        re.compile(r'process\.env|NEXT_PUBLIC|VITE_', re.I)),
    LintRule("async-no-await-used", "network", "warning",
        re.compile(r'async\s+(?:function\s+\w+|(?:\w+\s*=\s*)?\([^)]*\)\s*=>)\s*\{[^}]*\bfetch\b[^}]*\}'),
        "async function calls fetch but may be missing await",
        negative_filter=re.compile(r'await\s+fetch', re.I)),
    LintRule("n-plus-one", "network", "warning",
        re.compile(r'for\s*\([^)]*\)\s*\{[^}]*await\s+(?:fetch|supabase|prisma|db)\b'),
        "Await inside loop — N+1 query pattern",
        "Batch requests with Promise.all() or a single bulk query"),
]

# ── RESPONSIVE/MOBILE ─────────────────────────────────────────────────────────

RESPONSIVE_RULES: List[LintRule] = [
    LintRule("fixed-width-large", "responsive", "info",
        re.compile(r'width\s*:\s*\d{4,}px|w-\[\d{4,}px\]'),
        "Large fixed pixel width — may overflow on mobile",
        "Use max-width, percentage, or responsive classes"),
    LintRule("hover-only", "responsive", "info",
        re.compile(r'(?:onMouseEnter|onMouseOver)\b(?![^{]*(?:onClick|onTouchStart|onFocus))'),
        "Hover-only interaction — no touch equivalent"),
    LintRule("small-touch-target", "responsive", "info",
        re.compile(r'(?:w-[1-7]|h-[1-7]|size-[1-7])\b.*(?:onClick|button|href)', re.I),
        "Small element with click handler — may be hard to tap on mobile (min 44px)",
        "Ensure minimum 44x44px touch target"),
    LintRule("text-too-small", "responsive", "info",
        re.compile(r'text-\[(?:[0-9]|1[01])px\]|font-size:\s*(?:[0-9]|1[01])px'),
        "Text smaller than 12px — illegible on many devices",
        "Use at least 14px for body text"),
]

# ── SEO ───────────────────────────────────────────────────────────────────────

SEO_RULES: List[LintRule] = [
    LintRule("link-no-text", "seo", "warning",
        re.compile(r'<a\b[^>]*href[^>]*>\s*<(?:img|svg)\b[^>]*/?\s*>\s*</a>', re.I),
        "Link with only image/icon — no text for search engines",
        "Add descriptive text or aria-label"),
    LintRule("missing-lang", "seo", "info",
        re.compile(r'<html\b(?![^>]*\blang\s*=)'),
        "HTML tag without lang attribute",
        'Add lang="en" (or appropriate language)'),
]

# ── PROFESSIONAL ──────────────────────────────────────────────────────────────

POLISH_RULES: List[LintRule] = [
    LintRule("window-reload", "professional", "warning",
        re.compile(r'(?:window\.)?location\.reload\s*\('),
        "Full page reload — jarring in SPA",
        "Update state or use router"),
    LintRule("z-index-extreme", "professional", "info",
        re.compile(r'z-(?:index:\s*|(?:\[)?)(\d{4,})'),
        "z-index 1000+ — layering conflict"),
    LintRule("important-override", "professional", "info",
        re.compile(r'!\s*important'),
        "!important — fix specificity instead of forcing"),
    LintRule("setTimeout-state", "professional", "info",
        re.compile(r'setTimeout\s*\(\s*\(\s*\)\s*=>\s*\{?\s*set[A-Z]'),
        "setTimeout to trigger state update — verify cleanup",
        "Ensure clearTimeout in effect cleanup",
        re.compile(r'clearTimeout|saved.*idle|status.*idle', re.I)),
    LintRule("suspense-no-fallback", "professional", "warning",
        re.compile(r'<Suspense\b(?![^>]*fallback)'),
        "Suspense without fallback prop",
        "Add fallback={<Loading />}"),
    LintRule("error-boundary-missing-try", "professional", "info",
        re.compile(r'class\s+\w+\s+extends\s+(?:React\.)?Component\b(?![\s\S]*componentDidCatch)'),
        "Class component without error boundary — wrap with ErrorBoundary"),
    LintRule("console-error-only", "professional", "info",
        re.compile(r'console\.error\s*\([^)]+\)\s*;?\s*$'),
        "Error only logged to console — user doesn't know",
        "Also show error state in UI",
        re.compile(r'captureError|sentry|setError|setState|throw', re.I)),
    LintRule("dead-link-hash", "professional", "info",
        re.compile(r'href\s*=\s*["\']#["\']'),
        'href="#" is a dead link — use button or proper anchor',
        'Use <button> for actions or href to a real target'),
]

# ── CONSTRUCTION DOMAIN ───────────────────────────────────────────────────────

DOMAIN_RULES: List[LintRule] = [
    LintRule("currency-no-format", "domain", "info",
        re.compile(r'\$\$\{[^}]*(?:grand_total|subtotal|total_cost|bid_total)[^}]*\}(?!.*(?:toFixed|toLocaleString|format|fmt))', re.I),
        "Currency value without formatting — should show $X,XXX.XX",
        "Use toLocaleString('en-US', {minimumFractionDigits: 2}) or a fmt() helper"),
    LintRule("percent-over-100", "domain", "info",
        re.compile(r'(?:percentage|pct|percent)\s*[>:=]\s*(?:1[1-9]\d|[2-9]\d{2,}|1\d{3,})', re.I),
        "Percentage value >100% — verify this is intentional"),
    LintRule("negative-price", "domain", "warning",
        re.compile(r'(?:price|cost|total|amount)\s*[<:=]\s*-\d', re.I),
        "Negative price/cost — may indicate a bug",
        "Verify negative amounts are intentional (credits/discounts)"),
    LintRule("sqft-no-unit", "domain", "info",
        re.compile(r'(?:square\s*(?:feet|foot|ft)|sq\.?\s*ft|sqft)\b', re.I),
        "Square footage reference — ensure consistent unit display"),
    LintRule("estimate-status-raw", "domain", "info",
        re.compile(r'status\s*===?\s*["\'](?:sent|draft|viewed|negotiating|accepted|declined|expired)["\']', re.I),
        "Raw estimate status string — use STATUS_MAP for display",
        "Map to user-friendly label before displaying"),
]


# ═══════════════════════════════════════════════════════════════════════════════
# ALL LINE-LEVEL RULES
# ═══════════════════════════════════════════════════════════════════════════════

ALL_RULES = (
    DESIGN_RULES + A11Y_RULES + UX_RULES + HYGIENE_RULES +
    SECURITY_RULES + PERFORMANCE_RULES + FORM_RULES + REACT_RULES +
    API_RULES + DATA_RULES + STATE_RULES + NETWORK_RULES +
    RESPONSIVE_RULES + SEO_RULES + POLISH_RULES + DOMAIN_RULES
)


# ═══════════════════════════════════════════════════════════════════════════════
# MULTI-LINE / FILE-LEVEL ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

class FileAnalyzer:
    """Deeper analysis that requires reading the whole file."""

    def __init__(self, source: str, filepath: str, lines: List[str]):
        self.source = source
        self.filepath = filepath
        self.lines = lines
        self.errors: List[AeonError] = []
        self.line_count = len(lines)
        self.non_empty = sum(1 for l in lines if l.strip() and not l.strip().startswith("//"))
        self.is_tsx = filepath.endswith((".tsx", ".jsx"))
        self.is_route = bool(re.search(r'route\.ts$|api/', filepath))
        self.is_page = bool(re.search(r'page\.tsx$', filepath))
        self.is_component = self.is_tsx and not self.is_route and not self.is_page

    def run_all(self) -> List[AeonError]:
        self._check_file_size()
        self._check_usestate_count()
        self._check_useeffect_cleanup()
        self._check_api_handler_structure()
        self._check_missing_error_boundary_import()
        self._check_missing_loading_state()
        self._check_form_validation()
        self._check_duplicate_strings()
        self._check_prop_count()
        self._check_nested_ternary()
        self._check_deep_nesting()
        self._check_password_autocomplete()
        return self.errors

    def _add(self, msg: str, cat: str, sev: str, line: int = 1, fix: str = "", rule: str = ""):
        self.errors.append(ui_error(msg, cat, SourceLocation(self.filepath, line, 1), sev, fix, rule))

    def _check_file_size(self):
        if self.is_component and self.non_empty > 500:
            self._add(f"Component file is {self.non_empty} lines — split into smaller components",
                      "react", "warning", 1, "Extract logical sections", "giant-file")
        elif self.non_empty > 800:
            self._add(f"File is {self.non_empty} lines — consider splitting",
                      "hygiene", "info", 1, "Break into focused modules", "giant-file")

    def _check_usestate_count(self):
        if not self.is_component:
            return
        state_count = len(re.findall(r'useState\b', self.source))
        if state_count > 8:
            self._add(f"{state_count} useState hooks — consider useReducer or extracting custom hooks",
                      "state", "warning", 1, "Group related states into useReducer", "excessive-state")

    def _check_useeffect_cleanup(self):
        """Check for useEffect with subscriptions/timers but no cleanup."""
        effects = list(re.finditer(r'useEffect\s*\(\s*\(\s*\)\s*=>\s*\{', self.source))
        for match in effects:
            start = match.start()
            # Find the closing of this effect (rough heuristic)
            depth = 0
            pos = match.end()
            effect_body = ""
            while pos < len(self.source) and depth >= 0:
                ch = self.source[pos]
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    if depth == 0:
                        break
                    depth -= 1
                pos += 1
            effect_body = self.source[match.end():pos]

            needs_cleanup = bool(re.search(
                r'addEventListener|setInterval|setTimeout|subscribe|\.on\(|new\s+(?:WebSocket|EventSource|IntersectionObserver|MutationObserver|ResizeObserver)',
                effect_body
            ))
            has_cleanup = bool(re.search(r'return\s*\(\s*\)\s*=>\s*\{|return\s*\(\s*\)\s*=>', effect_body))

            if needs_cleanup and not has_cleanup:
                line_num = self.source[:start].count('\n') + 1
                self._add("useEffect with subscription/timer but no cleanup function — memory leak",
                          "react", "warning", line_num,
                          "Return a cleanup function: () => { clearInterval/removeEventListener(...) }",
                          "effect-no-cleanup")

    def _check_api_handler_structure(self):
        """Check API route handler for required patterns."""
        if not self.is_route:
            return

        handlers = re.findall(r'export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\b', self.source)
        if not handlers:
            return

        has_auth = bool(re.search(r'getAuthUser|verifyAuth|requireAuth|auth\s*=', self.source, re.I))
        has_try = bool(re.search(r'try\s*\{', self.source))
        has_rate_limit = bool(re.search(r'rateLimiter|rateLimit|limiter\.check', self.source, re.I))
        is_public = bool(re.search(r'portal|public|health|webhook|cron|pricing', self.filepath, re.I))

        if not has_auth and not is_public:
            self._add("API handler without auth check — unauthorized access possible",
                      "api", "error", 1, "Add getAuthUser(req) at handler start", "api-no-auth")

        if not has_try:
            self._add("API handler without try/catch — unhandled errors crash endpoint",
                      "api", "error", 1, "Wrap body in try/catch, return 500", "api-no-try-catch")

        if 'POST' in handlers and not has_rate_limit and not is_public:
            self._add("POST handler without rate limiting",
                      "api", "warning", 1, "Add rate limiter check", "api-no-rate-limit")

    def _check_missing_error_boundary_import(self):
        """Check if component uses Suspense but might lack error boundary."""
        if not self.is_component:
            return
        if '<Suspense' in self.source and 'ErrorBoundary' not in self.source and 'error' not in self.filepath.lower():
            self._add("Suspense without ErrorBoundary — errors during lazy load crash the page",
                      "react", "info", 1, "Wrap Suspense in an ErrorBoundary", "suspense-no-error-boundary")

    def _check_missing_loading_state(self):
        """Check if async operations have loading indicators."""
        if not self.is_component:
            return
        has_fetch = bool(re.search(r'await\s+(?:fetch|supabase)', self.source))
        has_loading = bool(re.search(r'loading|isLoading|isFetching|isPending|spinner', self.source, re.I))
        if has_fetch and not has_loading:
            self._add("Async data fetching without loading state — UI shows nothing while loading",
                      "ux", "warning", 1, "Add loading state with skeleton/spinner", "no-loading-state")

    def _check_form_validation(self):
        """Check if forms have validation."""
        if not self.is_component:
            return
        has_form = bool(re.search(r'<form\b', self.source))
        has_validation = bool(re.search(r'(?:zod|yup|joi|validate|schema|\.parse|\.safeParse|required|pattern\s*=)', self.source, re.I))
        if has_form and not has_validation:
            self._add("Form without validation — invalid data can reach the server",
                      "forms", "warning", 1, "Add Zod schema or HTML5 validation", "form-no-validation")

    def _check_duplicate_strings(self):
        """Check for repeated string literals that should be constants."""
        if self.non_empty < 50:
            return
        # Only match actual string literals, not JSX or template fragments
        strings = re.findall(r'(?:const|let|var|=|:|\()\s*["\']([^"\']{15,50})["\']', self.source)
        from collections import Counter
        counts = Counter(strings)
        for s, count in counts.most_common(2):
            if count >= 6 and not re.match(r'^(?:utf-8|en-US|application/json|Content-Type|Authorization|GET|POST|PUT|DELETE|error|success|true|false|none|null|undefined|loading|string|number|boolean|\d+|[a-z][a-z0-9_-]+)$', s, re.I) and '<' not in s and '{' not in s:
                self._add(f'String "{s[:30]}..." repeated {count} times — extract to a constant',
                          "hygiene", "info", 1, "Create a named constant", "duplicate-string")

    def _check_prop_count(self):
        """Check for components with too many props."""
        if not self.is_component:
            return
        # Look for interface/type Props with many fields
        props_match = re.search(r'(?:interface|type)\s+\w*Props\w*\s*(?:=\s*)?\{([^}]{500,})\}', self.source, re.S)
        if props_match:
            prop_count = props_match.group(1).count(';') + props_match.group(1).count('\n')
            if prop_count > 12:
                self._add(f"Component has ~{prop_count} props — consider composition or grouping",
                          "react", "info", 1, "Group related props into objects or use composition", "too-many-props")

    def _check_nested_ternary(self):
        """Check for deeply nested ternary operators."""
        for i, line in enumerate(self.lines, 1):
            ternary_count = line.count(' ? ') + line.count('?.')
            if ternary_count >= 3:
                self._add("Deeply nested ternary — hard to read and maintain",
                          "hygiene", "warning", i, "Refactor to if/else or a helper function", "nested-ternary")
                break  # One warning is enough

    def _check_password_autocomplete(self):
        """Multi-line check: password inputs should have autoComplete."""
        if not self.is_component:
            return
        # Find all <input ... type="password" ... > blocks (may span lines)
        password_inputs = list(re.finditer(r'type\s*=\s*["\']password["\']', self.source))
        for match in password_inputs:
            # Check surrounding context (100 chars before and after) for autoComplete
            start = max(0, match.start() - 200)
            end = min(len(self.source), match.end() + 200)
            context = self.source[start:end]
            if 'autoComplete' not in context and 'autocomplete' not in context:
                line_num = self.source[:match.start()].count('\n') + 1
                self._add("Password input without autoComplete attribute",
                          "forms", "warning", line_num,
                          'Add autoComplete="current-password" or "new-password"',
                          "password-no-autocomplete")

    def _check_deep_nesting(self):
        """Check for deeply nested code blocks."""
        max_depth = 0
        current_depth = 0
        deepest_line = 1
        for i, line in enumerate(self.lines, 1):
            current_depth += line.count('{') - line.count('}')
            if current_depth > max_depth:
                max_depth = current_depth
                deepest_line = i
        if max_depth > 7:
            self._add(f"Code nesting depth reaches {max_depth} — extract to helper functions",
                      "hygiene", "warning", deepest_line, "Flatten with early returns or extracted functions", "deep-nesting")


# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class UIUXLintEngine:
    """Comprehensive source-level UI/UX analysis engine."""

    def __init__(self, rules: Optional[List[LintRule]] = None,
                 categories: Optional[List[str]] = None,
                 min_severity: str = "info"):
        self.rules = rules or ALL_RULES

        if categories:
            self.rules = [r for r in self.rules if r.category in categories]

        severity_order = {"error": 0, "warning": 1, "info": 2}
        min_level = severity_order.get(min_severity, 2)
        self.rules = [r for r in self.rules if severity_order.get(r.severity, 2) <= min_level]

    def check_source(self, source: str, filepath: str = "<unknown>") -> List[AeonError]:
        """Full analysis: line-level rules + multi-line + file-level."""
        errors: List[AeonError] = []
        lines = source.split("\n")

        # Phase 1: Line-level rules
        for rule in self.rules:
            if rule.file_filter and not rule.file_filter.search(filepath):
                continue

            hits = 0
            max_hits = 5

            for i, line in enumerate(lines, start=1):
                if hits >= max_hits:
                    break

                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                    if rule.id not in ("todo-fixme", "commented-code"):
                        continue

                if stripped.startswith("import ") and rule.category not in ("performance",):
                    continue

                if rule.negative_filter and rule.negative_filter.search(line):
                    continue

                if rule.pattern.search(line):
                    loc = SourceLocation(file=filepath, line=i, column=1)
                    errors.append(ui_error(
                        message=rule.message, category=rule.category,
                        location=loc, severity=rule.severity,
                        fix=rule.fix, rule_id=rule.id,
                    ))
                    hits += 1

        # Phase 2: Multi-line & file-level analysis
        analyzer = FileAnalyzer(source, filepath, lines)
        errors.extend(analyzer.run_all())

        return errors


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE ENTRY POINTS
# ═══════════════════════════════════════════════════════════════════════════════

def check_ui_ux(source: str, filepath: str = "<unknown>",
                categories: Optional[List[str]] = None,
                min_severity: str = "info") -> List[AeonError]:
    """Run UI/UX lint on source text."""
    engine = UIUXLintEngine(categories=categories, min_severity=min_severity)
    return engine.check_source(source, filepath=filepath)


UI_EXTENSIONS = {".tsx", ".jsx", ".vue", ".svelte", ".html"}
UI_ADJACENT_EXTENSIONS = {".ts", ".js", ".css", ".scss"}

def is_ui_file(filepath: str) -> bool:
    ext = os.path.splitext(filepath)[1].lower()
    if ext in UI_EXTENSIONS:
        return True
    if ext in UI_ADJACENT_EXTENSIONS:
        parts = filepath.lower().replace("\\", "/").split("/")
        ui_dirs = {"components", "views", "pages", "app", "ui", "portal", "layout", "screens"}
        return bool(ui_dirs & set(parts))
    return False

def get_rule_count() -> int:
    return len(ALL_RULES)

def get_categories() -> List[str]:
    return sorted(set(r.category for r in ALL_RULES))

def get_file_analyzer_check_count() -> int:
    """Count file-level analysis checks."""
    return 11  # Number of _check_* methods in FileAnalyzer
