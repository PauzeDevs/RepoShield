(() => {
  "use strict";

  const canvas = document.querySelector("#ambient-field");
  if (!canvas) return;

  const context = canvas.getContext("2d", { alpha: true });
  if (!context) return;

  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const pointer = { x: -1000, y: -1000 };
  let width = 0;
  let height = 0;
  let frame = 0;
  let points = [];
  let running = true;

  const palette = [
    "rgba(58, 157, 255, ",
    "rgba(75, 220, 255, ",
    "rgba(135, 160, 255, "
  ];

  function createPoints() {
    const area = width * height;
    const count = Math.max(24, Math.min(78, Math.round(area / 19000)));

    points = Array.from({ length: count }, (_, index) => ({
      x: Math.random() * width,
      y: Math.random() * height,
      radius: 0.7 + Math.random() * 1.4,
      speedX: (Math.random() - 0.5) * 0.16,
      speedY: (Math.random() - 0.5) * 0.16,
      phase: Math.random() * Math.PI * 2,
      color: palette[index % palette.length]
    }));
  }

  function resize() {
    const ratio = Math.min(window.devicePixelRatio || 1, 1.5);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    canvas.style.width = width + "px";
    canvas.style.height = height + "px";
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    createPoints();
    draw(0, true);
  }

  function draw(time, staticFrame = false) {
    context.clearRect(0, 0, width, height);
    const linkDistance = width < 640 ? 105 : 145;
    const timeFactor = staticFrame || reducedMotion.matches ? 0 : time * 0.00025;

    for (const point of points) {
      if (!staticFrame && !reducedMotion.matches) {
        point.x += point.speedX;
        point.y += point.speedY;

        if (point.x < -12) point.x = width + 12;
        if (point.x > width + 12) point.x = -12;
        if (point.y < -12) point.y = height + 12;
        if (point.y > height + 12) point.y = -12;
      }

      const pulse = 0.42 + (Math.sin(timeFactor + point.phase) + 1) * 0.18;
      const dx = point.x - pointer.x;
      const dy = point.y - pointer.y;
      const distanceToPointer = Math.hypot(dx, dy);
      const glow = distanceToPointer < 180 ? 0.22 * (1 - distanceToPointer / 180) : 0;

      context.beginPath();
      context.fillStyle = point.color + Math.min(0.85, pulse + glow) + ")";
      context.arc(point.x, point.y, point.radius + glow * 2, 0, Math.PI * 2);
      context.fill();
    }

    for (let index = 0; index < points.length; index++) {
      const point = points[index];
      for (let nextIndex = index + 1; nextIndex < points.length; nextIndex++) {
        const next = points[nextIndex];
        const distance = Math.hypot(point.x - next.x, point.y - next.y);
        if (distance >= linkDistance) continue;

        const opacity = (1 - distance / linkDistance) * 0.17;
        context.beginPath();
        context.strokeStyle = "rgba(83, 157, 235, " + opacity + ")";
        context.lineWidth = 0.7;
        context.moveTo(point.x, point.y);
        context.lineTo(next.x, next.y);
        context.stroke();
      }
    }
  }

  function animate(time) {
    if (!running) return;
    draw(time);
    if (!reducedMotion.matches) frame = window.requestAnimationFrame(animate);
  }

  function start() {
    window.cancelAnimationFrame(frame);
    if (reducedMotion.matches) {
      draw(0, true);
      return;
    }
    running = true;
    frame = window.requestAnimationFrame(animate);
  }

  canvas.setAttribute("aria-hidden", "true");
  window.addEventListener("resize", resize, { passive: true });
  window.addEventListener("pointermove", event => {
    pointer.x = event.clientX;
    pointer.y = event.clientY;
  }, { passive: true });
  window.addEventListener("pointerleave", () => {
    pointer.x = -1000;
    pointer.y = -1000;
  }, { passive: true });
  document.addEventListener("visibilitychange", () => {
    running = !document.hidden;
    if (running) start();
    else window.cancelAnimationFrame(frame);
  });
  reducedMotion.addEventListener?.("change", start);

  resize();
  start();
})();
