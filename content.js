/**
 * LessPass Password Field Detector PoC - Content Script
 */

(function () {
  // Prevent double injection
  if (window.__lesspass_poc_loaded) return;
  window.__lesspass_poc_loaded = true;

  // LessPass Pure JS Algorithm Implementation
  const LessPass = {
    characterSubsets: {
      lowercase: "abcdefghijklmnopqrstuvwxyz",
      uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      digits: "0123456789",
      symbols: "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
    },

    getAlgorithm(algorithm) {
      const algorithms = {
        sha1: "SHA-1",
        "sha-1": "SHA-1",
        sha256: "SHA-256",
        "sha-256": "SHA-256",
        sha512: "SHA-512",
        "sha-512": "SHA-512",
      };
      const lowercaseAlgorithm = algorithm.toLowerCase();
      if (lowercaseAlgorithm in algorithms) {
        return algorithms[lowercaseAlgorithm];
      }
      return "SHA-256";
    },

    stringToArrayBuffer(s) {
      const base64String = unescape(encodeURIComponent(s));
      const charList = base64String.split("");
      const arrayBuffer = [];
      for (let i = 0; i < charList.length; i += 1) {
        arrayBuffer.push(charList[i].charCodeAt(0));
      }
      return new Uint8Array(arrayBuffer);
    },

    arrayBufferToHex(arrayBuffer) {
      const byteArray = new Uint8Array(arrayBuffer);
      let str = "";
      for (let i = 0; i < byteArray.byteLength; i += 1) {
        str += byteArray[i].toString(16).padStart(2, "0");
      }
      return str;
    },

    pbkdf2(password, salt, iterations, keylen, digest) {
      return window.crypto.subtle
        .importKey("raw", this.stringToArrayBuffer(password), "PBKDF2", false, [
          "deriveKey",
        ])
        .then((key) => {
          const algo = {
            name: "PBKDF2",
            salt: this.stringToArrayBuffer(salt),
            iterations,
            hash: this.getAlgorithm(digest),
          };
          return window.crypto.subtle.deriveKey(
            algo,
            key,
            {
              name: "AES-CTR",
              length: keylen * 8,
            },
            true,
            ["encrypt", "decrypt"],
          );
        })
        .then((derivedKey) =>
          window.crypto.subtle
            .exportKey("raw", derivedKey)
            .then((keyArray) => this.arrayBufferToHex(keyArray)),
        );
    },

    divMod(dividend, divisor) {
      return {
        quotient: divisor > 0n ? dividend / divisor : BigInt(0),
        remainder: dividend % divisor,
      };
    },

    consumeEntropy(generatedPassword, quotient, setOfCharacters, maxLength) {
      let passwordBuilt = generatedPassword;
      if (passwordBuilt.length >= maxLength) {
        return { value: passwordBuilt, entropy: quotient };
      }
      const longDivision = this.divMod(quotient, BigInt(setOfCharacters.length));
      passwordBuilt += setOfCharacters[Number(longDivision.remainder)];
      return this.consumeEntropy(
        passwordBuilt,
        longDivision.quotient,
        setOfCharacters,
        maxLength,
      );
    },

    getSetOfCharacters(rules) {
      let setOfChars = "";
      rules.forEach((rule) => {
        setOfChars += this.characterSubsets[rule];
      });
      return setOfChars;
    },

    getOneCharPerRule(entropy, rules) {
      let oneCharPerRules = "";
      let consumedEntropy = entropy;
      rules.forEach((rule) => {
        const password = this.consumeEntropy(
          "",
          consumedEntropy,
          this.characterSubsets[rule],
          1,
        );
        oneCharPerRules += password.value;
        consumedEntropy = password.entropy;
      });
      return { value: oneCharPerRules, entropy: consumedEntropy };
    },

    getRules(options) {
      const rules = ["lowercase", "uppercase", "digits", "symbols"];
      return rules.filter((rule) => options[rule]);
    },

    insertStringPseudoRandomly(initialString, entropy, stringToInsert) {
      let consumedEntropy = entropy;
      let string = initialString;
      for (let i = 0; i < stringToInsert.length; i += 1) {
        const longDivision = this.divMod(consumedEntropy, BigInt(string.length));
        const remainder = Number(longDivision.remainder);
        string =
          string.slice(0, remainder) + stringToInsert[i] + string.slice(remainder);
        consumedEntropy = longDivision.quotient;
      }
      return string;
    },

    generatePassword(profile, masterPassword) {
      const {
        site,
        login,
        length,
        counter,
        lowercase,
        uppercase,
        digits,
        symbols,
      } = profile;

      const rules = this.getRules({ lowercase, uppercase, digits, symbols });
      if (rules.length === 0) {
        return Promise.reject(new Error("At least one character class must be selected"));
      }
      const setOfCharacters = this.getSetOfCharacters(rules);
      const salt = site + login + counter.toString(16);

      return this.pbkdf2(masterPassword, salt, 100000, 32, "sha256")
        .then((entropy) => {
          const generatedPassword = this.consumeEntropy(
            "",
            BigInt(`0x${entropy}`),
            setOfCharacters,
            length - rules.length
          );
          const charactersToAdd = this.getOneCharPerRule(
            generatedPassword.entropy,
            rules
          );
          const finalPassword = this.insertStringPseudoRandomly(
            generatedPassword.value,
            charactersToAdd.entropy,
            charactersToAdd.value
          );
          return finalPassword;
        });
    }
  };

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

      // Add modern, high-end styling inside Shadow DOM matching the requested layout
      const style = document.createElement('style');
      style.textContent = `
        :host {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          box-sizing: border-box;
        }

        /* Float Icon Button */
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

        /* Popover Form Card - Dark Mode */
        .popover {
          position: absolute;
          width: 360px;
          background: #0f0f11;
          color: #ffffff;
          border-radius: 12px;
          box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.3);
          border: 1px solid #232326;
          padding: 16px;
          pointer-events: auto;
          display: flex;
          flex-direction: column;
          gap: 12px;
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
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 13px;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          color: #9ca3af;
          border-bottom: 1px solid #232326;
          padding-bottom: 8px;
          margin-bottom: 4px;
        }

        .form-group {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        label {
          font-size: 12px;
          font-weight: 600;
          color: #e5e7eb;
        }

        input[type="text"],
        input[type="password"],
        input[type="number"] {
          background: #16161a;
          border: 1px solid #323236;
          color: #ffffff;
          padding: 8px 10px;
          border-radius: 6px;
          font-size: 13px;
          outline: none;
          box-sizing: border-box;
          transition: border-color 0.15s ease, box-shadow 0.15s ease;
          width: 100%;
        }

        input[type="text"]:focus,
        input[type="password"]:focus,
        input[type="number"]:focus {
          border-color: #3b82f6;
          box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.3);
        }

        /* Checkboxes styling */
        .options-row {
          display: flex;
          align-items: center;
          gap: 8px;
          flex-wrap: wrap;
        }

        .checkbox-container {
          display: flex;
          align-items: center;
          gap: 4px;
          font-size: 12px;
          color: #9ca3af;
          cursor: pointer;
          user-select: none;
        }

        .checkbox-container input {
          cursor: pointer;
          accent-color: #3b82f6;
          width: 15px;
          height: 15px;
        }

        /* Length & Counter Layout */
        .bottom-inputs {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 12px;
        }

        /* Buttons Layout */
        .action-btn {
          width: 100%;
          background: #3b82f6;
          color: white;
          border: none;
          padding: 10px;
          font-size: 13px;
          font-weight: 600;
          border-radius: 6px;
          cursor: pointer;
          transition: background 0.15s ease, transform 0.1s ease;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 6px;
          margin-top: 4px;
        }

        .action-btn:hover {
          background: #2563eb;
        }

        .action-btn:active {
          transform: scale(0.98);
        }

        .action-btn.generating {
          background: #1d4ed8;
          cursor: not-allowed;
          opacity: 0.8;
        }
      `;

      // Float Trigger Button
      this.iconBtn = document.createElement('button');
      this.iconBtn.className = 'icon-btn';
      this.iconBtn.setAttribute('title', 'LessPass Generator');
      this.iconBtn.innerHTML = `
        <svg viewBox="0 0 24 24">
          <path d="M12.63 2a9.14 9.14 0 0 0-9 9.14c0 3.32 5.17 10.3 8.35 10.74a1 1 0 0 0 .65-.13l3-1.8a1 1 0 0 0 .37-.78v-1.63h1.8a1 1 0 0 0 .71-.29l1.8-1.8a1 1 0 0 0 .29-.71v-3.6a9.14 9.14 0 0 0-8-9.14zm3.17 12.18l-1.8 1.8a1 1 0 0 0-.29.71v1.63l-2.07 1.25c-2.47-.94-6.44-7.2-6.44-9.63a7.14 7.14 0 0 1 14 0v3.6a1 1 0 0 0-.4 1.14z"/>
          <circle cx="12.63" cy="8" r="2" />
        </svg>
      `;

      // Get Default Hostname
      const defaultSite = window.location.hostname.replace(/^www\./, '');

      // Create Popover Layout matching the screenshot precisely
      this.popover = document.createElement('div');
      this.popover.className = 'popover';
      this.popover.innerHTML = `
        <div class="popover-header">
          <svg style="width: 14px; height: 14px; fill: currentColor;" viewBox="0 0 24 24">
            <path d="M12.63 2a9.14 9.14 0 0 0-9 9.14c0 3.32 5.17 10.3 8.35 10.74a1 1 0 0 0 .65-.13l3-1.8a1 1 0 0 0 .37-.78v-1.63h1.8a1 1 0 0 0 .71-.29l1.8-1.8a1 1 0 0 0 .29-.71v-3.6a9.14 9.14 0 0 0-8-9.14zm3.17 12.18l-1.8 1.8a1 1 0 0 0-.29.71v1.63l-2.07 1.25c-2.47-.94-6.44-7.2-6.44-9.63a7.14 7.14 0 0 1 14 0v3.6a1 1 0 0 0-.4 1.14z"/>
            <circle cx="12.63" cy="8" r="2" />
          </svg>
          LessPass Stateless Generator
        </div>
        
        <div class="form-group">
          <label>Site</label>
          <input type="text" id="lp-site" value="${defaultSite}">
        </div>

        <div class="form-group">
          <label>Login</label>
          <input type="text" id="lp-login" placeholder="email or username">
        </div>

        <div class="form-group">
          <label>Master password</label>
          <input type="password" id="lp-master-password" placeholder="master password">
        </div>

        <div class="form-group">
          <label>Options</label>
          <div class="options-row">
            <label class="checkbox-container">
              <input type="checkbox" id="lp-opt-lowercase" checked> a-z
            </label>
            <label class="checkbox-container">
              <input type="checkbox" id="lp-opt-uppercase" checked> A-Z
            </label>
            <label class="checkbox-container">
              <input type="checkbox" id="lp-opt-digits" checked> 0-9
            </label>
            <label class="checkbox-container">
              <input type="checkbox" id="lp-opt-symbols" checked> %!@
            </label>
          </div>
        </div>

        <div class="bottom-inputs">
          <div class="form-group">
            <label>Length</label>
            <input type="number" id="lp-length" value="16" min="6" max="35">
          </div>
          <div class="form-group">
            <label>Counter</label>
            <input type="number" id="lp-counter" value="1" min="1">
          </div>
        </div>

        <button class="action-btn" id="lp-generate">
          Generate & Fill
        </button>
      `;

      this.shadow.appendChild(style);
      this.shadow.appendChild(this.iconBtn);
      this.shadow.appendChild(this.popover);

      document.body.appendChild(this.container);
    }

    reposition() {
      if (this.input.offsetWidth === 0 || this.input.offsetHeight === 0 || !document.body.contains(this.input)) {
        this.container.style.display = 'none';
        return;
      }

      this.container.style.display = 'block';

      const rect = this.input.getBoundingClientRect();
      const scrollX = window.scrollX || window.pageXOffset;
      const scrollY = window.scrollY || window.pageYOffset;

      const btnSize = 22;
      
      const btnTop = rect.top + scrollY + (rect.height - btnSize) / 2;
      const btnLeft = rect.right + scrollX - btnSize - 6;

      this.iconBtn.style.top = `${btnTop}px`;
      this.iconBtn.style.left = `${btnLeft}px`;

      const popoverWidth = 360;
      const popoverTop = btnTop + btnSize + 6;
      const popoverLeft = btnLeft + btnSize - popoverWidth;

      this.popover.style.top = `${popoverTop}px`;
      this.popover.style.left = `${popoverLeft}px`;
    }

    setupEventListeners() {
      this.iconBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        this.togglePopover();
      });

      const generateBtn = this.popover.querySelector('#lp-generate');
      generateBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        this.generateAndFill();
      });

      // Prevent clicks inside the popover from bubbling and closing it
      this.popover.addEventListener('click', (e) => {
        e.stopPropagation();
      });

      document.addEventListener('click', this.handleOutsideClick.bind(this));

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
        this.reposition();
        
        // Auto focus the master password field for speed
        setTimeout(() => {
          const masterInput = this.popover.querySelector('#lp-master-password');
          if (masterInput) masterInput.focus();
        }, 50);
      } else {
        this.iconBtn.classList.remove('open');
        this.popover.classList.remove('visible');
      }
    }

    async generateAndFill() {
      const site = this.popover.querySelector('#lp-site').value.trim();
      const login = this.popover.querySelector('#lp-login').value.trim();
      const masterPassword = this.popover.querySelector('#lp-master-password').value;
      const length = parseInt(this.popover.querySelector('#lp-length').value, 10) || 16;
      const counter = parseInt(this.popover.querySelector('#lp-counter').value, 10) || 1;

      const lowercase = this.popover.querySelector('#lp-opt-lowercase').checked;
      const uppercase = this.popover.querySelector('#lp-opt-uppercase').checked;
      const digits = this.popover.querySelector('#lp-opt-digits').checked;
      const symbols = this.popover.querySelector('#lp-opt-symbols').checked;

      if (!masterPassword) {
        alert("Master password is required");
        return;
      }

      if (!lowercase && !uppercase && !digits && !symbols) {
        alert("Please select at least one option");
        return;
      }

      const generateBtn = this.shadow.querySelector('#lp-generate');
      generateBtn.textContent = 'Generating...';
      generateBtn.classList.add('generating');

      try {
        const profile = {
          site,
          login,
          length,
          counter,
          lowercase,
          uppercase,
          digits,
          symbols
        };

        const generatedPassword = await LessPass.generatePassword(profile, masterPassword);
        
        // Fill Password into host page password input
        this.input.value = generatedPassword;
        this.input.dispatchEvent(new Event('input', { bubbles: true }));
        this.input.dispatchEvent(new Event('change', { bubbles: true }));

        // Soft pulse animation on the input field to give nice success feedback
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

        // Reset state & close popover
        this.popover.querySelector('#lp-master-password').value = ''; // Clean master password for security
        this.togglePopover();
      } catch (err) {
        console.error("LessPass generation failed:", err);
        alert("Generation failed: " + err.message);
      } finally {
        generateBtn.textContent = 'Generate & Fill';
        generateBtn.classList.remove('generating');
      }
    }

    handleOutsideClick(e) {
      if (!this.isOpen) return;

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
