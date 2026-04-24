(function() {
  function parseHSL(hslStr) {
    const match = hslStr.match(/([\d.]+)\s*([\d.]+)%?\s*([\d.]+)%?/);
    if (!match) return { h: 40, s: 80, l: 80 };
    return { h: parseFloat(match[1]), s: parseFloat(match[2]), l: parseFloat(match[3]) };
  }

  function buildGlowVars(glowColor, intensity) {
    const { h, s, l } = parseHSL(glowColor);
    const base = `${h}deg ${s}% ${l}%`;
    const opacities = [100, 60, 50, 40, 30, 20, 10];
    const keys = ['', '-60', '-50', '-40', '-30', '-20', '-10'];
    const vars = {};
    for (let i = 0; i < opacities.length; i++) {
      vars[`--glow-color${keys[i]}`] = `hsl(${base} / ${Math.min(opacities[i] * intensity, 100)}%)`;
    }
    return vars;
  }

  const GRADIENT_POSITIONS = ['80% 55%', '69% 34%', '8% 6%', '41% 38%', '86% 85%', '82% 18%', '51% 4%'];
  const GRADIENT_KEYS = ['--gradient-one', '--gradient-two', '--gradient-three', '--gradient-four', '--gradient-five', '--gradient-six', '--gradient-seven'];
  const COLOR_MAP = [0, 1, 2, 0, 1, 2, 1];

  function buildGradientVars(colors) {
    const vars = {};
    for (let i = 0; i < 7; i++) {
      const c = colors[Math.min(COLOR_MAP[i], colors.length - 1)];
      vars[GRADIENT_KEYS[i]] = `radial-gradient(at ${GRADIENT_POSITIONS[i]}, ${c} 0px, transparent 50%)`;
    }
    vars['--gradient-base'] = `linear-gradient(${colors[0]} 0 100%)`;
    return vars;
  }

  function easeOutCubic(x) { return 1 - Math.pow(1 - x, 3); }
  function easeInCubic(x) { return x * x * x; }

  function animateValue({ start = 0, end = 100, duration = 1000, delay = 0, ease = easeOutCubic, onUpdate, onEnd }) {
    const t0 = performance.now() + delay;
    function tick() {
      const elapsed = performance.now() - t0;
      if (elapsed < 0) {
        requestAnimationFrame(tick);
        return;
      }
      const t = Math.min(elapsed / duration, 1);
      onUpdate(start + (end - start) * ease(t));
      if (t < 1) requestAnimationFrame(tick);
      else if (onEnd) onEnd();
    }
    requestAnimationFrame(tick);
  }

  function initBorderGlow(card) {
    const config = {
      edgeSensitivity: parseFloat(card.dataset.glowEdgeSensitivity) || 30,
      glowColor: card.dataset.glowColor || '290 100 65', // Matching magenta theme
      backgroundColor: card.dataset.glowBg || 'rgba(10, 10, 15, 0.85)',
      borderRadius: parseFloat(card.dataset.glowRadius) || 12, // More button-like radius
      glowRadius: parseFloat(card.dataset.glowPadding) || 40,
      glowIntensity: parseFloat(card.dataset.glowIntensity) || 1.0,
      coneSpread: parseFloat(card.dataset.glowConeSpread) || 25,
      animated: card.dataset.glowAnimated !== 'false',
      colors: card.dataset.glowColors ? card.dataset.glowColors.split(',') : ['#a855f7', '#e100ff', '#ec4899'],
      fillOpacity: parseFloat(card.dataset.glowFillOpacity) || 0.5,
    };

    // Apply inline styles
    card.style.setProperty('--card-bg', config.backgroundColor);
    card.style.setProperty('--edge-sensitivity', config.edgeSensitivity);
    card.style.setProperty('--border-radius', `${config.borderRadius}px`);
    card.style.setProperty('--glow-padding', `${config.glowRadius}px`);
    card.style.setProperty('--cone-spread', config.coneSpread);
    card.style.setProperty('--fill-opacity', config.fillOpacity);

    const glowVars = buildGlowVars(config.glowColor, config.glowIntensity);
    Object.entries(glowVars).forEach(([k, v]) => card.style.setProperty(k, v));

    const gradientVars = buildGradientVars(config.colors);
    Object.entries(gradientVars).forEach(([k, v]) => card.style.setProperty(k, v));

    // Wrap content if not already wrapped
    if (!card.querySelector('.border-glow-inner')) {
      const inner = document.createElement('div');
      inner.className = 'border-glow-inner';
      while (card.firstChild) {
        inner.appendChild(card.firstChild);
      }
      card.appendChild(inner);
    }

    if (!card.querySelector('.edge-light')) {
      const edgeLight = document.createElement('span');
      edgeLight.className = 'edge-light';
      card.insertBefore(edgeLight, card.firstChild);
    }

    const getCenterOfElement = (el) => {
      const rect = el.getBoundingClientRect();
      return [rect.width / 2, rect.height / 2];
    };

    const getEdgeProximity = (el, x, y) => {
      const [cx, cy] = getCenterOfElement(el);
      const dx = x - cx;
      const dy = y - cy;
      let kx = Infinity;
      let ky = Infinity;
      if (dx !== 0) kx = cx / Math.abs(dx);
      if (dy !== 0) ky = cy / Math.abs(dy);
      return Math.min(Math.max(1 / Math.min(kx, ky), 0), 1);
    };

    const getCursorAngle = (el, x, y) => {
      const [cx, cy] = getCenterOfElement(el);
      const dx = x - cx;
      const dy = y - cy;
      if (dx === 0 && dy === 0) return 0;
      const radians = Math.atan2(dy, dx);
      let degrees = radians * (180 / Math.PI) + 90;
      if (degrees < 0) degrees += 360;
      return degrees;
    };

    card.addEventListener('pointermove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      const edge = getEdgeProximity(card, x, y);
      const angle = getCursorAngle(card, x, y);

      card.style.setProperty('--edge-proximity', `${(edge * 100).toFixed(3)}`);
      card.style.setProperty('--cursor-angle', `${angle.toFixed(3)}deg`);
    });

    if (config.animated) {
      const angleStart = 110;
      const angleEnd = 465;
      card.classList.add('sweep-active');
      card.style.setProperty('--cursor-angle', `${angleStart}deg`);

      animateValue({ duration: 500, onUpdate: v => card.style.setProperty('--edge-proximity', v) });
      animateValue({ ease: easeInCubic, duration: 1500, end: 50, onUpdate: v => {
        card.style.setProperty('--cursor-angle', `${(angleEnd - angleStart) * (v / 100) + angleStart}deg`);
      }});
      animateValue({ ease: easeOutCubic, delay: 1500, duration: 2250, start: 50, end: 100, onUpdate: v => {
        card.style.setProperty('--cursor-angle', `${(angleEnd - angleStart) * (v / 100) + angleStart}deg`);
      }});
      animateValue({ ease: easeInCubic, delay: 2500, duration: 1500, start: 100, end: 0,
        onUpdate: v => card.style.setProperty('--edge-proximity', v),
        onEnd: () => card.classList.remove('sweep-active'),
      });
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.border-glow-card').forEach(initBorderGlow);
  });
})();
