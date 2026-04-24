/* ===== CUSTOM CURSOR ===== */
const glow = document.getElementById('cursor-glow');

// Create dot + ring cursor elements
const dot = document.createElement('div');
dot.className = 'custom-cursor';
const ring = document.createElement('div');
ring.className = 'cursor-ring';
document.body.appendChild(dot);
document.body.appendChild(ring);

let mouseX = 0, mouseY = 0;
let ringX = 0, ringY = 0;

document.addEventListener('mousemove', (e) => {
  mouseX = e.clientX;
  mouseY = e.clientY;

  // Dot follows instantly
  dot.style.left = mouseX + 'px';
  dot.style.top = mouseY + 'px';

  // Glow follows cursor (fixed position)
  glow.style.left = mouseX + 'px';
  glow.style.top = mouseY + 'px';
});

// Ring follows with smooth lag
function animateRing() {
  ringX += (mouseX - ringX) * 0.12;
  ringY += (mouseY - ringY) * 0.12;
  ring.style.left = ringX + 'px';
  ring.style.top = ringY + 'px';
  requestAnimationFrame(animateRing);
}
animateRing();

// Cursor grow on hover
document.querySelectorAll('a, button, .feature-card, .problem-card, .redteam-card').forEach(el => {
  el.addEventListener('mouseenter', () => {
    dot.style.width = '8px';
    dot.style.height = '8px';
    dot.style.background = '#e100ff';
    ring.style.width = '54px';
    ring.style.height = '54px';
    ring.style.borderColor = 'rgba(225,0,255,0.6)';
  });
  el.addEventListener('mouseleave', () => {
    dot.style.width = '12px';
    dot.style.height = '12px';
    dot.style.background = '#a855f7';
    ring.style.width = '36px';
    ring.style.height = '36px';
    ring.style.borderColor = 'rgba(168,85,247,0.5)';
  });
});

/* ===== NAVBAR SCROLL ===== */
const navbar = document.getElementById('navbar');
window.addEventListener('scroll', () => {
  if (window.scrollY > 60) {
    navbar.classList.add('scrolled');
  } else {
    navbar.classList.remove('scrolled');
  }
}, { passive: true });

/* ===== SCROLL REVEAL ===== */
const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach((entry, i) => {
    if (entry.isIntersecting) {
      // Stagger children in same parent
      const siblings = entry.target.parentElement.querySelectorAll('.reveal');
      let delay = 0;
      siblings.forEach((sib, idx) => {
        if (sib === entry.target) delay = idx * 80;
      });
      setTimeout(() => {
        entry.target.classList.add('visible');
      }, delay);
      revealObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });

document.querySelectorAll('.reveal').forEach(el => revealObserver.observe(el));

/* ===== COUNTER ANIMATION ===== */
function animateCounter(el) {
  const target = parseInt(el.dataset.target, 10);
  const duration = 1800;
  const start = performance.now();
  const update = (now) => {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // ease-out-cubic
    el.textContent = Math.floor(eased * target);
    if (progress < 1) requestAnimationFrame(update);
    else el.textContent = target;
  };
  requestAnimationFrame(update);
}

const counterObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      animateCounter(entry.target);
      counterObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.5 });

document.querySelectorAll('.stat-num[data-target]').forEach(el => counterObserver.observe(el));

/* ===== SCORE RING ANIMATION ===== */
const ringObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.style.strokeDashoffset = getComputedStyle(entry.target).getPropertyValue('--pct');
      entry.target.classList.add('animated');
      ringObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.5 });

document.querySelectorAll('.ring-fill').forEach(el => ringObserver.observe(el));

/* ===== SMOOTH ANCHOR SCROLL ===== */
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', (e) => {
    const target = document.querySelector(anchor.getAttribute('href'));
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

/* ===== FOOTER EMAIL FORM ===== */
const form = document.getElementById('email-form');
if (form) {
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const input = document.getElementById('email-input');
    const btn = document.getElementById('email-submit');
    if (input.value) {
      btn.textContent = '✓';
      btn.style.background = 'linear-gradient(135deg,#22c55e,#16a34a)';
      input.value = '';
      input.placeholder = 'You\'re on the list!';
      setTimeout(() => {
        btn.textContent = '→';
        btn.style.background = '';
        input.placeholder = 'you@enterprise.com';
      }, 3000);
    }
  });
}

/* Parallax orbs removed — replaced by WebGL aurora in aurora.js */

/* ===== CARD MOUSE TILT ===== */
document.querySelectorAll('.feature-card, .problem-card, .redteam-card').forEach(card => {
  card.addEventListener('mousemove', (e) => {
    const rect = card.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width - 0.5) * 10;
    const y = ((e.clientY - rect.top) / rect.height - 0.5) * 10;
    card.style.transform = `perspective(600px) rotateY(${x}deg) rotateX(${-y}deg) translateY(-3px)`;
  });
  card.addEventListener('mouseleave', () => {
    card.style.transform = '';
  });
});
