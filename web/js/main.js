/* ═══════════════════════════════════════════════════════════
   AEON — Shared JavaScript (navbar, scroll effects, counters)
   ═══════════════════════════════════════════════════════════ */

/* ── Navbar scroll effect ──────────────────────────────── */
const nav = document.getElementById('navbar');
if (nav) {
    window.addEventListener('scroll', () => {
        nav.classList.toggle('scrolled', window.scrollY > 20);
    });
}

/* ── Mobile menu toggle ────────────────────────────────── */
function toggleMobile() {
    const links = document.querySelector('.nav-links');
    if (links) links.classList.toggle('open');
}

/* ── Scroll fade-in ────────────────────────────────────── */
const observer = new IntersectionObserver((entries) => {
    entries.forEach(e => {
        if (e.isIntersecting) {
            e.target.classList.add('visible');
            observer.unobserve(e.target);
        }
    });
}, { threshold: 0.15 });

document.querySelectorAll('.fade-in').forEach(el => observer.observe(el));

/* ── Stat counter animation ────────────────────────────── */
let statsCounted = false;
const statsEl = document.querySelector('.stats');
if (statsEl) {
    const statsObserver = new IntersectionObserver((entries) => {
        if (entries[0].isIntersecting && !statsCounted) {
            statsCounted = true;
            document.querySelectorAll('.stat-number[data-target]').forEach(el => {
                const target = parseInt(el.dataset.target);
                if (target === 0) { el.textContent = '0'; return; }
                let current = 0;
                const step = Math.max(1, Math.floor(target / 40));
                const timer = setInterval(() => {
                    current += step;
                    if (current >= target) { current = target; clearInterval(timer); }
                    el.textContent = current;
                }, 30);
            });
        }
    }, { threshold: 0.5 });
    statsObserver.observe(statsEl);
}

/* ── Generic tab switcher ──────────────────────────────── */
function showTab(id, btn) {
    document.querySelectorAll('.install-block').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-btn, .install-tab').forEach(b => b.classList.remove('active'));
    const tabEl = document.getElementById('tab-' + id);
    if (tabEl) tabEl.classList.add('active');
    if (btn) btn.classList.add('active');
}
