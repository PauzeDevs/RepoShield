(() => {
  "use strict";
  const canvas = document.querySelector("#ambient-field");
  if (!canvas) return;
  const ctx = canvas.getContext("2d", { alpha: true });
  if (!ctx) return;

  const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const pointer = { x: 0, y: 0, active: false };
  let width = 1, height = 1, ratio = 1, frame = 0, lastFrame = 0;
  let particles = [], started = false;

  const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
  const palette = ["#a9ddf5", "#73b8ff", "#b4c9ff"];

  function resize() {
    ratio = Math.min(window.devicePixelRatio || 1, 1.5);
    width = Math.max(1, document.documentElement.clientWidth || window.innerWidth);
    height = Math.max(1, window.innerHeight);
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    canvas.style.width = width + "px";
    canvas.style.height = height + "px";
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    const count = clamp(Math.round(width * height / 16000), 22, width < 640 ? 34 : 62);
    particles = Array.from({ length: count }, (_, index) => ({
      x: Math.random() * width, y: Math.random() * height,
      z: .25 + Math.random() * .75, r: .5 + Math.random() * 1.1,
      phase: Math.random() * Math.PI * 2, speed: .08 + Math.random() * .15,
      color: palette[index % palette.length]
    }));
    draw(0, true);
  }

  function project(x, y, z, cx, cy, focal) {
    const perspective = focal / Math.max(90, focal + z);
    return { x: cx + x * perspective, y: cy + y * perspective, scale: perspective };
  }

  function draw(time, still = false) {
    ctx.clearRect(0, 0, width, height);
    const t = still || motion.matches ? 0 : time * .00025;
    const px = pointer.active ? (pointer.x / width - .5) : 0;
    const py = pointer.active ? (pointer.y / height - .5) : 0;
    const cx = width * (.5 + px * .025);
    const horizon = height * .43 + py * 8;

    // Soft, low-contrast light source keeps the page readable.
    const glow = ctx.createRadialGradient(cx, horizon, 0, cx, horizon, Math.max(width, height) * .62);
    glow.addColorStop(0, "rgba(55,118,173,.10)");
    glow.addColorStop(.45, "rgba(37,79,125,.035)");
    glow.addColorStop(1, "rgba(5,7,11,0)");
    ctx.fillStyle = glow;
    ctx.fillRect(0, 0, width, height);

    // Perspective floor grid projected from a 3D coordinate system.
    ctx.save();
    ctx.lineWidth = .7;
    for (let row = 1; row <= 22; row++) {
      const z = row * row * 8 + 18;
      const y = horizon + 45 + (z * .62);
      if (y > height + 40) break;
      const alpha = Math.min(.12, .012 + row * .004);
      ctx.strokeStyle = "rgba(111,177,235," + alpha + ")";
      ctx.beginPath();
      ctx.moveTo(-width * .25, y);
      ctx.lineTo(width * 1.25, y);
      ctx.stroke();
    }
    for (let column = -16; column <= 16; column++) {
      const x = cx + column * (width / 19);
      ctx.strokeStyle = "rgba(111,177,235,.045)";
      ctx.beginPath();
      ctx.moveTo(cx + (x - cx) * .12, horizon);
      ctx.lineTo(cx + (x - cx) * 2.7, height * 1.2);
      ctx.stroke();
    }
    ctx.restore();

    // Rotating wireframe sphere: a real 3D projection rendered directly to canvas.
    const radius = Math.min(width, height) * (width < 640 ? .14 : .17);
    const sphereX = width * .77 + px * 24;
    const sphereY = height * .42 + py * 18;
    const rotateY = t * .65, rotateX = -.28 + Math.sin(t * .45) * .07;
    const projectSphere = (lat, lon) => {
      const x0 = radius * Math.cos(lat) * Math.cos(lon);
      const y0 = radius * Math.sin(lat);
      const z0 = radius * Math.cos(lat) * Math.sin(lon);
      const x1 = x0 * Math.cos(rotateY) - z0 * Math.sin(rotateY);
      const z1 = x0 * Math.sin(rotateY) + z0 * Math.cos(rotateY);
      const y1 = y0 * Math.cos(rotateX) - z1 * Math.sin(rotateX);
      const z2 = y0 * Math.sin(rotateX) + z1 * Math.cos(rotateX);
      return project(x1, y1, z2, sphereX, sphereY, radius * 3.5);
    };
    ctx.save();
    ctx.lineWidth = .65;
    for (let latIndex = -4; latIndex <= 4; latIndex++) {
      const lat = latIndex * Math.PI / 10;
      ctx.beginPath();
      for (let step = 0; step <= 72; step++) {
        const p = projectSphere(lat, step / 72 * Math.PI * 2);
        if (!step) ctx.moveTo(p.x, p.y); else ctx.lineTo(p.x, p.y);
      }
      ctx.strokeStyle = "rgba(139,199,241," + (latIndex === 0 ? ".20" : ".10") + ")";
      ctx.stroke();
    }
    for (let longitude = 0; longitude < 12; longitude++) {
      ctx.beginPath();
      for (let step = 0; step <= 64; step++) {
        const p = projectSphere(-Math.PI / 2 + step / 64 * Math.PI, longitude / 12 * Math.PI * 2);
        if (!step) ctx.moveTo(p.x, p.y); else ctx.lineTo(p.x, p.y);
      }
      ctx.strokeStyle = "rgba(139,199,241,.12)";
      ctx.stroke();
    }
    ctx.restore();

    for (const p of particles) {
      if (!still && !motion.matches) {
        p.y -= p.speed * p.z;
        p.x += Math.sin(t + p.phase) * .11;
        if (p.y < -12) { p.y = height + 12; p.x = Math.random() * width; }
      }
      const x = p.x + (pointer.active ? px * p.z * 15 : 0);
      const y = p.y + Math.sin(t + p.phase) * 5 * p.z;
      const alpha = .16 + p.z * .32;
      ctx.beginPath();
      ctx.fillStyle = p.color;
      ctx.globalAlpha = alpha;
      ctx.arc(x, y, p.r, 0, Math.PI * 2);
      ctx.fill();
      ctx.globalAlpha = 1;
    }

    const maxLink = width < 640 ? 76 : 110;
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const a = particles[i], b = particles[j];
        const distance = Math.hypot(a.x - b.x, a.y - b.y);
        if (distance > maxLink) continue;
        ctx.strokeStyle = "rgba(123,184,238," + ((1 - distance / maxLink) * .07) + ")";
        ctx.lineWidth = .55;
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
      }
    }
  }

  function animate(time) {
    if (document.hidden || motion.matches) { started = false; return; }
    if (time - lastFrame > 32) { draw(time); lastFrame = time; }
    frame = requestAnimationFrame(animate);
  }
  function start() {
    cancelAnimationFrame(frame);
    draw(0, motion.matches);
    started = !motion.matches && !document.hidden;
    if (started) frame = requestAnimationFrame(animate);
  }
  canvas.setAttribute("aria-hidden", "true");
  window.addEventListener("resize", resize, { passive: true });
  window.addEventListener("pointermove", event => {
    pointer.x = event.clientX; pointer.y = event.clientY; pointer.active = true;
  }, { passive: true });
  window.addEventListener("pointerleave", () => { pointer.active = false; }, { passive: true });
  document.addEventListener("visibilitychange", start);
  motion.addEventListener?.("change", start);
  resize();
  start();
})();