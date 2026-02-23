/* ═══════════════════════════════════════════════════════════
   AEON — Copy-to-Clipboard for Code Blocks
   Adds a "Copy" button to every <pre> element
   ═══════════════════════════════════════════════════════════ */

(function () {
    'use strict';

    function initCopyButtons() {
        document.querySelectorAll('pre').forEach(pre => {
            if (pre.querySelector('.copy-btn')) return;

            const wrapper = document.createElement('div');
            wrapper.className = 'code-block-wrapper';
            pre.parentNode.insertBefore(wrapper, pre);
            wrapper.appendChild(pre);

            const btn = document.createElement('button');
            btn.className = 'copy-btn';
            btn.setAttribute('aria-label', 'Copy code');
            btn.innerHTML = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg><span>Copy</span>`;
            wrapper.appendChild(btn);

            btn.addEventListener('click', () => {
                const code = pre.querySelector('code')
                    ? pre.querySelector('code').textContent
                    : pre.textContent;

                navigator.clipboard.writeText(code).then(() => {
                    btn.classList.add('copied');
                    btn.querySelector('span').textContent = 'Copied!';
                    setTimeout(() => {
                        btn.classList.remove('copied');
                        btn.querySelector('span').textContent = 'Copy';
                    }, 2000);
                }).catch(() => {
                    // Fallback for older browsers
                    const textarea = document.createElement('textarea');
                    textarea.value = code;
                    textarea.style.position = 'fixed';
                    textarea.style.opacity = '0';
                    document.body.appendChild(textarea);
                    textarea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textarea);
                    btn.classList.add('copied');
                    btn.querySelector('span').textContent = 'Copied!';
                    setTimeout(() => {
                        btn.classList.remove('copied');
                        btn.querySelector('span').textContent = 'Copy';
                    }, 2000);
                });
            });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initCopyButtons);
    } else {
        initCopyButtons();
    }
})();
