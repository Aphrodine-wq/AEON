/* ═══════════════════════════════════════════════════════════
   AEON — Particle Canvas Background
   Neural-network style connected dots with mouse interaction
   ═══════════════════════════════════════════════════════════ */
(function () {
    'use strict';
    try {

    const canvas = document.createElement('canvas');
    canvas.id = 'particle-canvas';
    canvas.style.cssText = 'position:fixed;inset:0;z-index:0;pointer-events:none;';
    document.body.prepend(canvas);

    const ctx = canvas.getContext('2d');
    let W, H, particles = [], mouse = { x: -9999, y: -9999 };
    const COUNT = 70;
    const CONNECT = 140;
    const MOUSE_R = 200;

    function resize() {
        W = canvas.width = window.innerWidth;
        H = canvas.height = window.innerHeight;
    }

    function spawn() {
        return {
            x: Math.random() * W,
            y: Math.random() * H,
            vx: (Math.random() - 0.5) * 0.4,
            vy: (Math.random() - 0.5) * 0.4,
            r: Math.random() * 1.8 + 0.8,
            o: Math.random() * 0.4 + 0.15,
        };
    }

    function init() {
        resize();
        particles = [];
        for (let i = 0; i < COUNT; i++) particles.push(spawn());
    }

    function frame() {
        ctx.clearRect(0, 0, W, H);

        for (let i = 0; i < particles.length; i++) {
            const a = particles[i];
            a.x += a.vx;
            a.y += a.vy;
            if (a.x < 0 || a.x > W) a.vx *= -1;
            if (a.y < 0 || a.y > H) a.vy *= -1;

            ctx.beginPath();
            ctx.arc(a.x, a.y, a.r, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(108,92,231,${a.o})`;
            ctx.fill();

            for (let j = i + 1; j < particles.length; j++) {
                const b = particles[j];
                const dx = a.x - b.x, dy = a.y - b.y;
                const d = Math.sqrt(dx * dx + dy * dy);
                if (d < CONNECT) {
                    ctx.beginPath();
                    ctx.moveTo(a.x, a.y);
                    ctx.lineTo(b.x, b.y);
                    ctx.strokeStyle = `rgba(108,92,231,${0.12 * (1 - d / CONNECT)})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }

            const mdx = a.x - mouse.x, mdy = a.y - mouse.y;
            const md = Math.sqrt(mdx * mdx + mdy * mdy);
            if (md < MOUSE_R) {
                ctx.beginPath();
                ctx.moveTo(a.x, a.y);
                ctx.lineTo(mouse.x, mouse.y);
                ctx.strokeStyle = `rgba(162,155,254,${0.25 * (1 - md / MOUSE_R)})`;
                ctx.lineWidth = 0.7;
                ctx.stroke();
            }
        }
        requestAnimationFrame(frame);
    }

    window.addEventListener('resize', resize);
    document.addEventListener('mousemove', e => { mouse.x = e.clientX; mouse.y = e.clientY; });
    document.addEventListener('mouseleave', () => { mouse.x = -9999; mouse.y = -9999; });

    init();
    frame();

    } catch (e) { /* particles are decorative — don't break the page */ }
})();
