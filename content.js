/**
 * LessPass Password Field Detector PoC - Content Script
 */

(function () {
  // Prevent double injection
  if (window.__lesspass_poc_loaded) return;
  window.__lesspass_poc_loaded = true;

  const activeHelpers = new Map();

  class PasswordHelper {
    constructor(input) {
      this.input = input;
      this.isOpen = false;
      this.createElements();
      this.reposition();
      this.setupEventListeners();
    }

    createElements() {
      // Create container that will hold our Shadow DOM
      this.container = document.createElement('div');
      this.container.className = 'lesspass-poc-helper-container';
      this.container.style.position = 'absolute';
      this.container.style.top = '0';
      this.container.style.left = '0';
      this.container.style.width = '100%';
      this.container.style.height = '0';
      this.container.style.overflow = 'visible';
      this.container.style.zIndex = '2147483647'; // Highest possible z-index
      this.container.style.pointerEvents = 'none';

      // Create Shadow Root for isolation
      this.shadow = this.container.attachShadow({ mode: 'open' });

      // Add modern, high-end styling inside Shadow DOM
      const style = document.createElement('style');
      style.textContent = `
        :host {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          box-sizing: border-box;
        }

        .icon-btn {
          position: absolute;
          width: 22px;
          height: 22px;
          border-radius: 50%;
          background: #3b82f6;
          border: none;
          cursor: pointer;
          pointer-events: auto;
          display: flex;
          align-items: center;
          justify-content: center;
          box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
          transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
          padding: 0;
          color: white;
          outline: none;
        }

        .icon-btn:hover {
          background: #2563eb;
          transform: scale(1.1);
          box-shadow: 0 3px 8px rgba(37, 99, 235, 0.4);
        }

        .icon-btn:active {
          transform: scale(0.95);
        }

        .icon-btn svg {
          width: 12px;
          height: 12px;
          fill: currentColor;
          transition: transform 0.2s ease;
        }

        .icon-btn.open svg {
          transform: rotate(45deg);
        }

        /* Popover Styling */
        .popover {
          position: absolute;
          width: 200px;
          background: #ffffff;
          border-radius: 12px;
          box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
          border: 1px solid #f3f4f6;
          padding: 12px;
          pointer-events: auto;
          display: flex;
          flex-direction: column;
          gap: 10px;
          opacity: 0;
          transform: translateY(-8px) scale(0.95);
          transform-origin: top right;
          transition: all 0.15s cubic-bezier(0.4, 0, 0.2, 1);
          visibility: hidden;
          z-index: 2147483647;
        }

        .popover.visible {
          opacity: 1;
          transform: translateY(0) scale(1);
          visibility: visible;
        }

        .popover-header {
          font-size: 11px;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          color: #9ca3af;
          margin-bottom: 2px;
        }

        .popover-body {
          font-size: 13px;
          color: #4b5563;
          line-height: 1.4;
        }

        .fill-btn {
          width: 100%;
          background: #10b981;
          color: white;
          border: none;
          padding: 8px 12px;
          font-size: 13px;
          font-weight: 500;
          border-radius: 6px;
          cursor: pointer;
          transition: background 0.15s ease, transform 0.1s ease;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 6px;
        }

        .fill-btn:hover {
          background: #059669;
        }

        .fill-btn:active {
          transform: scale(0.98);
        }
      `;

      // SVG Key Icon
      this.iconBtn = document.createElement('button');
      this.iconBtn.className = 'icon-btn';
      this.iconBtn.setAttribute('title', 'LessPass Quick Fill');
      this.iconBtn.innerHTML = `
        <svg viewBox="0 0 24 24">
          <path d="M12.63 2a9.14 9.14 0 0 0-9 9.14c0 3.32 5.17 10.3 8.35 10.74a1 1 0 0 0 .65-.13l3-1.8a1 1 0 0 0 .37-.78v-1.63h1.8a1 1 0 0 0 .71-.29l1.8-1.8a1 1 0 0 0 .29-.71v-3.6a9.14 9.14 0 0 0-8-9.14zm3.17 12.18l-1.8 1.8a1 1 0 0 0-.29.71v1.63l-2.07 1.25c-2.47-.94-6.44-7.2-6.44-9.63a7.14 7.14 0 0 1 14 0v3.6a1 1 0 0 0-.4 1.14z"/>
          <circle cx="12.63" cy="8" r="2" />
        </svg>
      `;

      // Create Popover
      this.popover = document.createElement('div');
      this.popover.className = 'popover';
      this.popover.innerHTML = `
        <div class="popover-header">LessPass PoC</div>
        <div class="popover-body">Ready to fill secure credential value.</div>
        <button class="fill-btn">
          <svg style="width: 14px; height: 14px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
            <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
            <line x1="12" y1="22.08" x2="12" y2="12"></line>
          </svg>
          Fill "testvalue"
        </button>
      `;

      this.shadow.appendChild(style);
      this.shadow.appendChild(this.iconBtn);
      this.shadow.appendChild(this.popover);

      document.body.appendChild(this.container);
    }

    reposition() {
      // Check if the input is currently visible
      if (this.input.offsetWidth === 0 || this.input.offsetHeight === 0 || !document.body.contains(this.input)) {
        this.container.style.display = 'none';
        return;
      }

      this.container.style.display = 'block';

      const rect = this.input.getBoundingClientRect();
      const scrollX = window.scrollX || window.pageXOffset;
      const scrollY = window.scrollY || window.pageYOffset;

      const btnSize = 22;
      
      // Place inside input on the far right, with a 6px margin
      const btnTop = rect.top + scrollY + (rect.height - btnSize) / 2;
      const btnLeft = rect.right + scrollX - btnSize - 6;

      this.iconBtn.style.top = `${btnTop}px`;
      this.iconBtn.style.left = `${btnLeft}px`;

      // Position popover directly below the button, aligned to its right edge
      const popoverWidth = 200;
      const popoverTop = btnTop + btnSize + 6;
      const popoverLeft = btnLeft + btnSize - popoverWidth;

      this.popover.style.top = `${popoverTop}px`;
      this.popover.style.left = `${popoverLeft}px`;
    }

    setupEventListeners() {
      // Toggle popover on button click
      this.iconBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        this.togglePopover();
      });

      // Fill action inside popover
      const fillBtn = this.popover.querySelector('.fill-btn');
      fillBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        this.fillPassword();
      });

      // Close popover when clicking anywhere else
      document.addEventListener('click', this.handleOutsideClick.bind(this));

      // Track size changes of the input to dynamic adjust helper positioning
      if (globalThis.ResizeObserver) {
        this.resizeObserver = new ResizeObserver(() => {
          this.reposition();
        });
        this.resizeObserver.observe(this.input);
      }
    }

    togglePopover() {
      this.isOpen = !this.isOpen;
      if (this.isOpen) {
        this.iconBtn.classList.add('open');
        this.popover.classList.add('visible');
        this.reposition(); // Reposition before opening to make sure coordinates are fresh
      } else {
        this.iconBtn.classList.remove('open');
        this.popover.classList.remove('visible');
      }
    }

    fillPassword() {
      // Direct assignment
      this.input.value = 'testvalue';

      // Dispatch appropriate events so any JS framework on the page updates its state
      this.input.dispatchEvent(new Event('input', { bubbles: true }));
      this.input.dispatchEvent(new Event('change', { bubbles: true }));

      // Soft pulse animation on the input field to give nice feedback
      const originalTransition = this.input.style.transition;
      const originalOutline = this.input.style.outline;
      
      this.input.style.transition = 'outline 0.2s ease, box-shadow 0.2s ease';
      this.input.style.outline = '2px solid #10b981';
      this.input.style.boxShadow = '0 0 8px rgba(16, 185, 129, 0.4)';

      setTimeout(() => {
        this.input.style.outline = originalOutline;
        this.input.style.boxShadow = '';
        setTimeout(() => {
          this.input.style.transition = originalTransition;
        }, 200);
      }, 800);

      // Close popover
      this.togglePopover();
    }

    handleOutsideClick(e) {
      if (!this.isOpen) return;

      // Check if click was inside our container/shadow DOM
      const path = e.composedPath();
      if (!path.includes(this.container)) {
        this.togglePopover();
      }
    }

    destroy() {
      if (this.resizeObserver) {
        this.resizeObserver.disconnect();
      }
      if (this.container && this.container.parentNode) {
        this.container.parentNode.removeChild(this.container);
      }
      document.removeEventListener('click', this.handleOutsideClick);
    }
  }

  // Scan and register helper
  function scanForPasswordFields() {
    const inputs = document.querySelectorAll('input[type="password"]');
    for (const input of inputs) {
      if (!activeHelpers.has(input)) {
        activeHelpers.set(input, new PasswordHelper(input));
      }
    }

    // Cleanup stale helpers
    for (const [input, helper] of activeHelpers.entries()) {
      if (!document.body.contains(input)) {
        helper.destroy();
        activeHelpers.delete(input);
      }
    }
  }

  function repositionAll() {
    for (const helper of activeHelpers.values()) {
      helper.reposition();
    }
  }

  // Initialize
  function init() {
    scanForPasswordFields();

    // Setup dynamic DOM observer to detect dynamically added password inputs
    const observer = new MutationObserver((mutations) => {
      let runScan = false;
      for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
          runScan = true;
          break;
        }
        if (mutation.type === 'attributes' && mutation.attributeName === 'type') {
          const target = mutation.target;
          if (target.tagName === 'INPUT' && target.type === 'password') {
            runScan = true;
            break;
          }
        }
      }
      if (runScan) {
        scanForPasswordFields();
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['type']
    });

    // Track scrolls, window resizes, and transitions
    window.addEventListener('scroll', repositionAll, { passive: true });
    window.addEventListener('resize', repositionAll, { passive: true });
    document.addEventListener('transitionend', repositionAll, { passive: true });
    document.addEventListener('animationend', repositionAll, { passive: true });
  }

  // Ensure DOM is fully loaded or active
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
