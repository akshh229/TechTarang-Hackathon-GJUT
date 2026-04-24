(function() {
  function initTextType(el) {
    const rawTexts = el.dataset.typeTexts;
    if (!rawTexts) return;
    let texts;
    try {
      texts = JSON.parse(rawTexts);
    } catch (e) {
      texts = [rawTexts];
    }
    if (!Array.isArray(texts)) texts = [texts];

    const config = {
      typingSpeed: parseInt(el.dataset.typeSpeed) || 50,
      initialDelay: parseInt(el.dataset.typeDelay) || 0,
      pauseDuration: parseInt(el.dataset.typePause) || 2000,
      deletingSpeed: parseInt(el.dataset.typeDeleteSpeed) || 30,
      loop: el.dataset.typeLoop !== 'false',
      cursorChar: el.dataset.typeCursor || '|',
      blinkDuration: parseFloat(el.dataset.typeBlink) || 0.5,
    };

    el.innerHTML = '';
    el.classList.add('text-type');
    
    const contentSpan = document.createElement('span');
    contentSpan.className = 'text-type__content';
    el.appendChild(contentSpan);

    const cursorSpan = document.createElement('span');
    cursorSpan.className = 'text-type__cursor';
    cursorSpan.innerHTML = config.cursorChar;
    el.appendChild(cursorSpan);

    // simple blink animation via CSS
    cursorSpan.style.animation = `blink ${config.blinkDuration * 2}s infinite`;

    let currentTextIndex = 0;
    let currentCharIndex = 0;
    let isDeleting = false;
    let displayedText = '';
    let timeout;

    function executeTypingAnimation() {
      const currentText = texts[currentTextIndex];

      if (isDeleting) {
        if (displayedText === '') {
          isDeleting = false;
          if (currentTextIndex === texts.length - 1 && !config.loop) {
            return;
          }
          currentTextIndex = (currentTextIndex + 1) % texts.length;
          currentCharIndex = 0;
          timeout = setTimeout(executeTypingAnimation, Math.max(500, config.initialDelay));
        } else {
          timeout = setTimeout(() => {
            displayedText = displayedText.slice(0, -1);
            contentSpan.textContent = displayedText;
            executeTypingAnimation();
          }, config.deletingSpeed);
        }
      } else {
        if (currentCharIndex < currentText.length) {
          timeout = setTimeout(() => {
            displayedText += currentText[currentCharIndex];
            contentSpan.textContent = displayedText;
            currentCharIndex++;
            executeTypingAnimation();
          }, config.typingSpeed);
        } else {
          if (!config.loop && currentTextIndex === texts.length - 1) return;
          timeout = setTimeout(() => {
            isDeleting = true;
            executeTypingAnimation();
          }, config.pauseDuration);
        }
      }
    }

    // Intersection observer to start when visible
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            timeout = setTimeout(executeTypingAnimation, config.initialDelay);
            observer.disconnect();
          }
        });
      },
      { threshold: 0.1 }
    );
    observer.observe(el);
  }

  document.addEventListener('DOMContentLoaded', () => {
    // Add blink keyframes to document
    const style = document.createElement('style');
    style.innerHTML = `
      @keyframes blink {
        0%, 100% { opacity: 1; }
        50% { opacity: 0; }
      }
    `;
    document.head.appendChild(style);

    document.querySelectorAll('.text-type-init').forEach(initTextType);
  });
})();
