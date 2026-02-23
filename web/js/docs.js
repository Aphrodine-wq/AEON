/* ═══════════════════════════════════════════════════════════
   AEON — Docs page sidebar navigation & search
   ═══════════════════════════════════════════════════════════ */

(function () {
    'use strict';

    const NAV_OFFSET = 80; // navbar height + padding

    // Smooth scroll helper with navbar offset
    function scrollToAnchor(href) {
        const target = document.querySelector(href);
        if (target) {
            const y = target.getBoundingClientRect().top + window.pageYOffset - NAV_OFFSET;
            window.scrollTo({ top: y, behavior: 'smooth' });
        }
    }

    // Smooth scroll for sidebar links
    document.querySelectorAll('.docs-sidebar a').forEach(link => {
        link.addEventListener('click', (e) => {
            const href = link.getAttribute('href');
            if (href && href.startsWith('#')) {
                e.preventDefault();
                scrollToAnchor(href);
                // Close mobile sidebar if open
                document.getElementById('docs-sidebar')?.classList.remove('open');
            }
        });
    });

    // Smooth scroll for right-side ToC links
    document.addEventListener('click', (e) => {
        const tocLink = e.target.closest('.docs-toc a');
        if (tocLink) {
            const href = tocLink.getAttribute('href');
            if (href && href.startsWith('#')) {
                e.preventDefault();
                scrollToAnchor(href);
            }
        }
    });
})();
