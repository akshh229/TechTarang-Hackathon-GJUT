/* ===== GlassSurface — Vanilla JS adaptation ===== */
(function () {
  let idCounter = 0;

  function createGlassElement(el) {
    const id = 'glass-' + (idCounter++);
    const filterId = 'glass-filter-' + id;
    const redGradId = 'red-grad-' + id;
    const blueGradId = 'blue-grad-' + id;

    // Read config from data attributes or use defaults
    const cfg = {
      borderRadius: parseFloat(el.dataset.glassRadius) || 12,
      borderWidth: parseFloat(el.dataset.glassBorderWidth) || 0.07,
      brightness: parseFloat(el.dataset.glassBrightness) || 50,
      opacity: parseFloat(el.dataset.glassOpacity) || 0.93,
      blur: parseFloat(el.dataset.glassBlur) || 11,
      displace: parseFloat(el.dataset.glassDisplace) || 0,
      backgroundOpacity: parseFloat(el.dataset.glassFrost) || 0,
      saturation: parseFloat(el.dataset.glassSaturation) || 1,
      distortionScale: parseFloat(el.dataset.glassDistortion) || -180,
      redOffset: parseFloat(el.dataset.glassRedOffset) || 0,
      greenOffset: parseFloat(el.dataset.glassGreenOffset) || 10,
      blueOffset: parseFloat(el.dataset.glassBlueOffset) || 20,
      xChannel: el.dataset.glassXChannel || 'R',
      yChannel: el.dataset.glassYChannel || 'G',
      mixBlendMode: el.dataset.glassBlend || 'difference',
    };

    // Detect SVG filter support
    const svgSupported = supportsSVGFilters(filterId);

    // Add class
    el.classList.add('glass-surface');
    el.classList.add(svgSupported ? 'glass-surface--svg' : 'glass-surface--fallback');

    // Set CSS vars
    el.style.setProperty('--glass-frost', cfg.backgroundOpacity);
    el.style.setProperty('--glass-saturation', cfg.saturation);
    el.style.setProperty('--filter-id', `url(#${filterId})`);
    el.style.borderRadius = cfg.borderRadius + 'px';

    // Create SVG filter
    const svgNS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(svgNS, 'svg');
    svg.classList.add('glass-surface__filter');
    svg.setAttribute('xmlns', svgNS);

    const defs = document.createElementNS(svgNS, 'defs');
    const filter = document.createElementNS(svgNS, 'filter');
    filter.setAttribute('id', filterId);
    filter.setAttribute('color-interpolation-filters', 'sRGB');
    filter.setAttribute('x', '0%');
    filter.setAttribute('y', '0%');
    filter.setAttribute('width', '100%');
    filter.setAttribute('height', '100%');

    // feImage
    const feImage = document.createElementNS(svgNS, 'feImage');
    feImage.setAttribute('x', '0');
    feImage.setAttribute('y', '0');
    feImage.setAttribute('width', '100%');
    feImage.setAttribute('height', '100%');
    feImage.setAttribute('preserveAspectRatio', 'none');
    feImage.setAttribute('result', 'map');

    // Red channel displacement
    const redDisp = document.createElementNS(svgNS, 'feDisplacementMap');
    redDisp.setAttribute('in', 'SourceGraphic');
    redDisp.setAttribute('in2', 'map');
    redDisp.setAttribute('result', 'dispRed');
    redDisp.setAttribute('scale', (cfg.distortionScale + cfg.redOffset).toString());
    redDisp.setAttribute('xChannelSelector', cfg.xChannel);
    redDisp.setAttribute('yChannelSelector', cfg.yChannel);

    const redMatrix = document.createElementNS(svgNS, 'feColorMatrix');
    redMatrix.setAttribute('in', 'dispRed');
    redMatrix.setAttribute('type', 'matrix');
    redMatrix.setAttribute('values', '1 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 1 0');
    redMatrix.setAttribute('result', 'red');

    // Green channel displacement
    const greenDisp = document.createElementNS(svgNS, 'feDisplacementMap');
    greenDisp.setAttribute('in', 'SourceGraphic');
    greenDisp.setAttribute('in2', 'map');
    greenDisp.setAttribute('result', 'dispGreen');
    greenDisp.setAttribute('scale', (cfg.distortionScale + cfg.greenOffset).toString());
    greenDisp.setAttribute('xChannelSelector', cfg.xChannel);
    greenDisp.setAttribute('yChannelSelector', cfg.yChannel);

    const greenMatrix = document.createElementNS(svgNS, 'feColorMatrix');
    greenMatrix.setAttribute('in', 'dispGreen');
    greenMatrix.setAttribute('type', 'matrix');
    greenMatrix.setAttribute('values', '0 0 0 0 0  0 1 0 0 0  0 0 0 0 0  0 0 0 1 0');
    greenMatrix.setAttribute('result', 'green');

    // Blue channel displacement
    const blueDisp = document.createElementNS(svgNS, 'feDisplacementMap');
    blueDisp.setAttribute('in', 'SourceGraphic');
    blueDisp.setAttribute('in2', 'map');
    blueDisp.setAttribute('result', 'dispBlue');
    blueDisp.setAttribute('scale', (cfg.distortionScale + cfg.blueOffset).toString());
    blueDisp.setAttribute('xChannelSelector', cfg.xChannel);
    blueDisp.setAttribute('yChannelSelector', cfg.yChannel);

    const blueMatrix = document.createElementNS(svgNS, 'feColorMatrix');
    blueMatrix.setAttribute('in', 'dispBlue');
    blueMatrix.setAttribute('type', 'matrix');
    blueMatrix.setAttribute('values', '0 0 0 0 0  0 0 0 0 0  0 0 1 0 0  0 0 0 1 0');
    blueMatrix.setAttribute('result', 'blue');

    // Blend channels
    const blend1 = document.createElementNS(svgNS, 'feBlend');
    blend1.setAttribute('in', 'red');
    blend1.setAttribute('in2', 'green');
    blend1.setAttribute('mode', 'screen');
    blend1.setAttribute('result', 'rg');

    const blend2 = document.createElementNS(svgNS, 'feBlend');
    blend2.setAttribute('in', 'rg');
    blend2.setAttribute('in2', 'blue');
    blend2.setAttribute('mode', 'screen');
    blend2.setAttribute('result', 'output');

    const gaussianBlur = document.createElementNS(svgNS, 'feGaussianBlur');
    gaussianBlur.setAttribute('in', 'output');
    gaussianBlur.setAttribute('stdDeviation', cfg.displace.toString());

    // Assemble filter
    filter.appendChild(feImage);
    filter.appendChild(redDisp);
    filter.appendChild(redMatrix);
    filter.appendChild(greenDisp);
    filter.appendChild(greenMatrix);
    filter.appendChild(blueDisp);
    filter.appendChild(blueMatrix);
    filter.appendChild(blend1);
    filter.appendChild(blend2);
    filter.appendChild(gaussianBlur);
    defs.appendChild(filter);
    svg.appendChild(defs);

    // Insert SVG into element
    el.insertBefore(svg, el.firstChild);

    // Generate displacement map
    function generateMap() {
      const rect = el.getBoundingClientRect();
      const w = rect.width || 200;
      const h = rect.height || 80;
      const edgeSize = Math.min(w, h) * (cfg.borderWidth * 0.5);

      const svgContent = `
        <svg viewBox="0 0 ${w} ${h}" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <linearGradient id="${redGradId}" x1="100%" y1="0%" x2="0%" y2="0%">
              <stop offset="0%" stop-color="#0000"/>
              <stop offset="100%" stop-color="red"/>
            </linearGradient>
            <linearGradient id="${blueGradId}" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stop-color="#0000"/>
              <stop offset="100%" stop-color="blue"/>
            </linearGradient>
          </defs>
          <rect x="0" y="0" width="${w}" height="${h}" fill="black"/>
          <rect x="0" y="0" width="${w}" height="${h}" rx="${cfg.borderRadius}" fill="url(#${redGradId})"/>
          <rect x="0" y="0" width="${w}" height="${h}" rx="${cfg.borderRadius}" fill="url(#${blueGradId})" style="mix-blend-mode: ${cfg.mixBlendMode}"/>
          <rect x="${edgeSize}" y="${edgeSize}" width="${w - edgeSize * 2}" height="${h - edgeSize * 2}" rx="${cfg.borderRadius}" fill="hsl(0 0% ${cfg.brightness}% / ${cfg.opacity})" style="filter:blur(${cfg.blur}px)"/>
        </svg>`;

      feImage.setAttribute('href', `data:image/svg+xml,${encodeURIComponent(svgContent)}`);
    }

    // Init + observe resize
    setTimeout(generateMap, 0);
    const ro = new ResizeObserver(() => setTimeout(generateMap, 0));
    ro.observe(el);
  }

  function supportsSVGFilters(filterId) {
    if (typeof window === 'undefined') return false;
    const isWebkit = /Safari/.test(navigator.userAgent) && !/Chrome/.test(navigator.userAgent);
    const isFirefox = /Firefox/.test(navigator.userAgent);
    if (isWebkit || isFirefox) return false;
    const div = document.createElement('div');
    div.style.backdropFilter = `url(#${filterId})`;
    return div.style.backdropFilter !== '';
  }

  // Init all .glass-btn elements on DOM ready
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.glass-btn').forEach(createGlassElement);
  });
})();
