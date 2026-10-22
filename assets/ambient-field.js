(() => {
  "use strict";
  const canvas = document.querySelector("#ambient-field");
  if (!canvas) return;
  const ctx = canvas.getContext("2d", { alpha: true });
  if (!ctx) return;
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
  const pointer = { x: 0, y: 0, active: false };
  let width = 1, height = 1, ratio = 1, frame = 0, lastFrame = 0, nodes = [];
  const colors = ["#a9ddf5", "#73b8ff", "#b4c9ff"];

  function resize() {
    ratio = Math.min(window.devicePixelRatio || 1, 1.5);
    width = Math.max(1, window.innerWidth);
    height = Math.max(1, window.innerHeight);
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    canvas.style.width = width + "px";
    canvas.style.height = height + "px";
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    const count = Math.max(28, Math.min(64, Math.round(width * height / 18000)));
    nodes = Array.from({ length: count }, (_, i) => ({
      x: Math.random() * width, y: Math.random() * height,
      z: .25 + Math.random() * .75, radius: .6 + Math.random(),
      phase: Math.random() * Math.PI * 2, drift: .08 + Math.random() * .16,
      color: colors[i % colors.length]
    }));
    draw(0, true);
  }

  function draw(time, still = false) {
    ctx.clearRect(0, 0, width, height);
    const centerX = width / 2 + (pointer.active ? (pointer.x - width / 2) * .025 : 0);
    const centerY = height * .47 + (pointer.active ? (pointer.y - height / 2) * .02 : 0);
    const t = still || reduced.matches ? 0 : time * .00022;
    ctx.save();
    ctx.translate(centerX, centerY);
    ctx.transform(1, 0, .16, .48, 0, 0);
    const horizon = -height * .1;
    for (let i = 0; i <= 13; i++) {
      const y = horizon + i * i * 2.15;
      if (y > height * 1.2) break;
      ctx.strokeStyle = "rgba(111,177,235," + Math.min(.11, .012 + i * .006) + ")";
      ctx.lineWidth = .7;
      ctx.beginPath(); ctx.moveTo(-width, y); ctx.lineTo(width, y); ctx.stroke();
    }
    for (let i = -14; i <= 14; i++) {
      ctx.strokeStyle = "rgba(111,177,235,.045)";
      ctx.beginPath(); ctx.moveTo(i * 54, horizon); ctx.lineTo(i * 118, height * 1.3); ctx.stroke();
    }
    ctx.restore();

    for (const node of nodes) {
      if (!still && !reduced.matches) {
        node.y -= node.drift * node.z;
        node.x += Math.sin(t + node.phase) * .08;
        if (node.y < -10) { node.y = height + 10; node.x = Math.random() * width; }
      }
      const x = node.x + (pointer.active ? (pointer.x - width / 2) * node.z * .012 : 0);
      const y = node.y + Math.sin(t + node.phase) * 7 * node.z;
      const glow = pointer.active ? Math.max(0, 1 - Math.hypot(pointer.x - x, pointer.y - y) / 190) : 0;
      ctx.beginPath(); ctx.fillStyle = node.color;
      ctx.globalAlpha = .22 + node.z * .35 + glow * .3;
      ctx.arc(x, y, node.radius + glow * 1.4, 0, Math.PI * 2); ctx.fill(); ctx.globalAlpha = 1;
    }
    const maxLink = width < 640 ? 82 : 120;
    for (let i = 0; i < nodes.length; i++) for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j], distance = Math.hypot(a.x - b.x, a.y - b.y);
      if (distance > maxLink) continue;
      ctx.strokeStyle = "rgba(123,184,238," + ((1 - distance / maxLink) * .095) + ")";
      ctx.lineWidth = .6; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
    }
  }

  function animate(time) {
    if (document.hidden || reduced.matches) return;
    if (time - lastFrame > 28) { draw(time); lastFrame = time; }
    frame = requestAnimationFrame(animate);
  }
  function start() {
    cancelAnimationFrame(frame);
    draw(0, reduced.matches);
    if (!reduced.matches && !document.hidden) frame = requestAnimationFrame(animate);
  }
  canvas.setAttribute("aria-hidden", "true");
  window.addEventListener("resize", resize, { passive: true });
  window.addEventListener("pointermove", event => { pointer.x = event.clientX; pointer.y = event.clientY; pointer.active = true; }, { passive: true });
  window.addEventListener("pointerleave", () => { pointer.active = false; }, { passive: true });
  document.addEventListener("visibilitychange", start);
  reduced.addEventListener?.("change", start);
  resize(); start();
})();