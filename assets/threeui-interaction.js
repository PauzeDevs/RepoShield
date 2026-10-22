(() => {
  "use strict";
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  if (reduceMotion.matches || !window.matchMedia("(hover: hover) and (pointer: fine)").matches) return;

  const cards = document.querySelectorAll(".scan-panel, .feature-card, .metric-card, .summary-card");
  const maxTilt = 3.2;

  cards.forEach(card => {
    let rect;
    let raf = 0;
    function reset() {
      cancelAnimationFrame(raf);
      card.style.transform = "";
      card.style.removeProperty("--pointer-x");
      card.style.removeProperty("--pointer-y");
    }
    card.addEventListener("pointerenter", () => { rect = card.getBoundingClientRect(); }, { passive: true });
    card.addEventListener("pointermove", event => {
      if (reduceMotion.matches) return;
      if (!rect) rect = card.getBoundingClientRect();
      const x = (event.clientX - rect.left) / rect.width;
      const y = (event.clientY - rect.top) / rect.height;
      const rotateY = (x - .5) * maxTilt * 2;
      const rotateX = (.5 - y) * maxTilt * 2;
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        card.style.transform = "perspective(1000px) rotateX(" + rotateX.toFixed(2) + "deg) rotateY(" + rotateY.toFixed(2) + "deg) translateZ(3px)";
        card.style.setProperty("--pointer-x", (x * 100).toFixed(1) + "%");
        card.style.setProperty("--pointer-y", (y * 100).toFixed(1) + "%");
      });
    }, { passive: true });
    card.addEventListener("pointerleave", reset, { passive: true });
    window.addEventListener("resize", () => { rect = null; reset(); }, { passive: true });
  });
})();