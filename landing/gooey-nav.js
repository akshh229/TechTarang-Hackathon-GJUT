(function() {
  function initGooeyNav(container) {
    const nav = container.querySelector('nav ul');
    if (!nav) return;
    
    // Add effect spans if they don't exist
    let filterSpan = container.querySelector('.effect.filter');
    let textSpan = container.querySelector('.effect.text');
    
    if (!filterSpan) {
      filterSpan = document.createElement('span');
      filterSpan.className = 'effect filter';
      container.appendChild(filterSpan);
    }
    if (!textSpan) {
      textSpan = document.createElement('span');
      textSpan.className = 'effect text';
      container.appendChild(textSpan);
    }

    const items = Array.from(nav.querySelectorAll('li'));
    let activeIndex = 0;
    
    const config = {
      animationTime: parseInt(container.dataset.animTime) || 600,
      particleCount: parseInt(container.dataset.particles) || 15,
      timeVariance: parseInt(container.dataset.variance) || 300,
      particleR: parseInt(container.dataset.radius) || 100,
      colors: [1, 2, 3, 1, 2, 3, 1, 4]
    };
    const distances = [90, 10];

    const noise = (n = 1) => n / 2 - Math.random() * n;
    const getXY = (distance, pointIndex, totalPoints) => {
      const angle = ((360 + noise(8)) / totalPoints) * pointIndex * (Math.PI / 180);
      return [distance * Math.cos(angle), distance * Math.sin(angle)];
    };

    const createParticle = (i, t) => {
      let rotate = noise(config.particleR / 10);
      return {
        start: getXY(distances[0], config.particleCount - i, config.particleCount),
        end: getXY(distances[1] + noise(7), config.particleCount - i, config.particleCount),
        time: t,
        scale: 1 + noise(0.2),
        color: config.colors[Math.floor(Math.random() * config.colors.length)],
        rotate: rotate > 0 ? (rotate + config.particleR / 20) * 10 : (rotate - config.particleR / 20) * 10
      };
    };

    const makeParticles = (element) => {
      const bubbleTime = config.animationTime * 2 + config.timeVariance;
      element.style.setProperty('--time', `${bubbleTime}ms`);

      for (let i = 0; i < config.particleCount; i++) {
        const t = config.animationTime * 2 + noise(config.timeVariance * 2);
        const p = createParticle(i, t);
        element.classList.remove('active');

        setTimeout(() => {
          const particle = document.createElement('span');
          const point = document.createElement('span');
          particle.classList.add('particle');
          particle.style.setProperty('--start-x', `${p.start[0]}px`);
          particle.style.setProperty('--start-y', `${p.start[1]}px`);
          particle.style.setProperty('--end-x', `${p.end[0]}px`);
          particle.style.setProperty('--end-y', `${p.end[1]}px`);
          particle.style.setProperty('--time', `${p.time}ms`);
          particle.style.setProperty('--scale', `${p.scale}`);
          particle.style.setProperty('--color', `var(--color-${p.color}, white)`);
          particle.style.setProperty('--rotate', `${p.rotate}deg`);

          point.classList.add('point');
          particle.appendChild(point);
          element.appendChild(particle);
          
          requestAnimationFrame(() => {
            element.classList.add('active');
          });
          
          setTimeout(() => {
            try {
              if (element.contains(particle)) {
                element.removeChild(particle);
              }
            } catch (e) {}
          }, t);
        }, 30);
      }
    };

    const updateEffectPosition = (element) => {
      const containerRect = container.getBoundingClientRect();
      const pos = element.getBoundingClientRect();
      const styles = {
        left: `${pos.x - containerRect.x}px`,
        top: `${pos.y - containerRect.y}px`,
        width: `${pos.width}px`,
        height: `${pos.height}px`
      };
      Object.assign(filterSpan.style, styles);
      Object.assign(textSpan.style, styles);
      textSpan.innerText = element.innerText;
    };

    const handleClick = (e, index) => {
      const liEl = e.currentTarget.closest('li');
      if (activeIndex === index) return;

      activeIndex = index;
      items.forEach((item, i) => {
        if (i === index) item.classList.add('active');
        else item.classList.remove('active');
      });

      updateEffectPosition(liEl);

      const particles = filterSpan.querySelectorAll('.particle');
      particles.forEach(p => p.remove());

      textSpan.classList.remove('active');
      void textSpan.offsetWidth; // trigger reflow
      textSpan.classList.add('active');

      makeParticles(filterSpan);
    };

    items.forEach((item, index) => {
      if (index === activeIndex) item.classList.add('active');
      const link = item.querySelector('a');
      if (link) {
        link.addEventListener('click', (e) => {
          handleClick(e, index);
        });
      }
      item.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handleClick(e, index);
        }
      });
    });

    // Initialize first item
    if (items.length > 0) {
      // Need to wait for layout to be complete before grabbing rects
      setTimeout(() => {
        updateEffectPosition(items[activeIndex]);
        textSpan.classList.add('active');
      }, 200);
    }

    const ro = new ResizeObserver(() => {
      if (items[activeIndex]) {
        updateEffectPosition(items[activeIndex]);
      }
    });
    ro.observe(container);
  }

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.gooey-nav-container').forEach(initGooeyNav);
  });
})();
