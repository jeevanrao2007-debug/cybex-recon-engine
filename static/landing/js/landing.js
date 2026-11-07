/**
 * Cybex Recon Engine · Video-First Landing Page Controller
 * Video playback management, boot sequence timing, and scroll reveal animations.
 */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
  initVideoPlayback();
  initBootSequence();
  initNavScroll();
  initScrollReveals();
});

/* ==========================================================================
   1. VIDEO PLAYBACK MANAGEMENT & FALLBACK LOGIC
   ========================================================================== */
function initVideoPlayback() {
  const video = document.getElementById("heroVideo");
  const canvas = document.getElementById("fallbackCanvas");

  if (!video) {
    console.warn("[Cybex Landing] Hero video element not found. Activating canvas fallback.");
    enableCanvasFallback(canvas);
    return;
  }

  // Canvas hidden by default via CSS display:none; activate only on failure
  // The <video autoplay> attribute handles playback — no manual .play() needed.

  // Detect successful playback start
  video.addEventListener("playing", () => {
    console.log("[Cybex Landing] Video 'cybex-hero.mp4' playing successfully.");
    if (canvas) canvas.style.display = "none";
  });

  // Detect load/decode errors
  video.addEventListener("error", (e) => {
    console.error("[Cybex Landing] Video error — activating canvas fallback:", e);
    enableCanvasFallback(canvas);
  });

  // Detect stalled / network timeout (file absent but no error event on some browsers)
  video.addEventListener("stalled", () => {
    console.warn("[Cybex Landing] Video stalled — activating canvas fallback.");
    enableCanvasFallback(canvas);
  });
}

function enableCanvasFallback(canvas) {
  const video = document.getElementById("heroVideo");
  if (video) video.style.display = "none";
  if (!canvas) return;

  canvas.style.display = "block";
  const ctx = canvas.getContext("2d");
  let width, height;

  const resize = () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  };
  resize();
  window.addEventListener("resize", resize, { passive: true });

  const nodes = [];
  for (let i = 0; i < 35; i++) {
    nodes.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      radius: Math.random() * 1.8 + 1,
      alpha: Math.random() * 0.5 + 0.2
    });
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = "#060911";
    ctx.fillRect(0, 0, width, height);

    for (let i = 0; i < nodes.length; i++) {
      const node = nodes[i];
      node.x += node.vx;
      node.y += node.vy;

      if (node.x < 0 || node.x > width) node.vx *= -1;
      if (node.y < 0 || node.y > height) node.vy *= -1;

      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(96, 165, 250, ${node.alpha})`;
      ctx.fill();

      for (let j = i + 1; j < nodes.length; j++) {
        const other = nodes[j];
        const dx = other.x - node.x;
        const dy = other.y - node.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 130) {
          ctx.beginPath();
          ctx.moveTo(node.x, node.y);
          ctx.lineTo(other.x, other.y);
          ctx.strokeStyle = `rgba(59, 130, 246, ${(1 - dist / 130) * 0.25})`;
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(draw);
  }

  draw();
}

/* ==========================================================================
   2. BOOT SEQUENCE CONTROLLER (1.6s Exact Sequence)
   ========================================================================== */
function initBootSequence() {
  const overlay = document.getElementById("bootOverlay");
  const progressFill = document.getElementById("bootProgressFill");
  const statusText = document.getElementById("bootStatusText");

  if (!overlay) return;

  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (prefersReducedMotion) {
    overlay.classList.add("boot-completed");
    return;
  }

  // 0.0s - 0.3s: Initial Dark State & Scanline
  // 0.6s: SYSTEM INITIALIZATION
  setTimeout(() => {
    if (statusText) statusText.textContent = "INITIALIZING CYBEX RECON ENGINE...";
    if (progressFill) progressFill.style.width = "40%";
  }, 300);

  setTimeout(() => {
    if (statusText) statusText.textContent = "LOADING INTELLIGENCE LAYER...";
    if (progressFill) progressFill.style.width = "75%";
  }, 600);

  // 1.2s: Video becomes visible behind boot sequence overlay
  setTimeout(() => {
    if (statusText) statusText.textContent = "SYSTEM READY.";
    if (progressFill) progressFill.style.width = "100%";
    overlay.classList.add("boot-reveal-video");
  }, 1200);

  // 1.6s: Boot overlay completes fade and hides
  setTimeout(() => {
    overlay.classList.add("boot-completed");
    setTimeout(() => {
      overlay.style.display = "none";
    }, 500);
  }, 1600);
}

/* ==========================================================================
   3. NAVIGATION BAR SCROLL & ACTIVE TRACKING
   ========================================================================== */
function initNavScroll() {
  const nav = document.getElementById("mainNav");
  if (!nav) return;

  const handleScroll = () => {
    if (window.scrollY > 40) {
      nav.classList.add("nav-scrolled");
    } else {
      nav.classList.remove("nav-scrolled");
    }
  };

  window.addEventListener("scroll", handleScroll, { passive: true });
  handleScroll();

  const sections = document.querySelectorAll("section[id], header[id]");
  const navLinks = document.querySelectorAll(".cybex-nav-links .nav-link-item");

  if ("IntersectionObserver" in window && sections.length && navLinks.length) {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const id = entry.target.getAttribute("id");
            navLinks.forEach((link) => {
              if (link.getAttribute("href") === `#${id}`) {
                link.classList.add("active");
              } else {
                link.classList.remove("active");
              }
            });
          }
        });
      },
      { threshold: 0.3 }
    );

    sections.forEach((section) => observer.observe(section));
  }
}

/* ==========================================================================
   4. SCROLL REVEALS
   ========================================================================== */
function initScrollReveals() {
  const revealItems = document.querySelectorAll(".reveal-item");
  if (!revealItems.length) return;

  if ("IntersectionObserver" in window) {
    const revealObserver = new IntersectionObserver(
      (entries, observer) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-revealed");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.12, rootMargin: "0px 0px -40px 0px" }
    );

    revealItems.forEach((item) => revealObserver.observe(item));
  } else {
    revealItems.forEach((item) => item.classList.add("is-revealed"));
  }
}
