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
  function getRegisteredDomain(hostname) {
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    
    // Common 2-part public suffixes
    const commonSecondLevelTlds = new Set([
      'co', 'com', 'org', 'net', 'edu', 'gov', 'mil', 'asn', 'id', 'or', 'ac', 'go'
    ]);
    
    const last = parts[parts.length - 1];
    const second = parts[parts.length - 2];
    
    // If the second to last part is one of the common second-level TLDs, and the last part is a standard ccTLD (usually 2 letters)
    if (commonSecondLevelTlds.has(second) && last.length === 2) {
      return parts.slice(-3).join('.');
    }
    
    return parts.slice(-2).join('.');
  }

  function findUsernameField(passwordInput) {
    const form = passwordInput.closest('form');
    if (form) {
      const inputs = form.querySelectorAll('input');
      const candidateInputs = Array.from(inputs).filter(input => {
        if (input === passwordInput) return false;
        const type = input.getAttribute('type') || 'text';
        return ['text', 'email', 'tel', 'url'].includes(type.toLowerCase());
      });

      let bestCandidate = null;
      let highestScore = -1;

      for (const input of candidateInputs) {
        let score = 0;
        const id = (input.id || '').toLowerCase();
        const name = (input.name || '').toLowerCase();
        const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
        const placeholder = (input.placeholder || '').toLowerCase();
        const className = (input.className || '').toLowerCase();
        const type = (input.getAttribute('type') || 'text').toLowerCase();

        if (type === 'email') score += 10;
        if (autocomplete === 'username' || autocomplete === 'email') score += 15;

        const keywords = ['user', 'email', 'login', 'usr', 'name', 'identifier'];
        for (const keyword of keywords) {
          if (id.includes(keyword)) score += 5;
          if (name.includes(keyword)) score += 5;
          if (placeholder.includes(keyword)) score += 5;
          if (className.includes(keyword)) score += 2;
        }

        if (score === 0 && candidateInputs.indexOf(input) === 0) score += 1;

        if (score > highestScore) {
          highestScore = score;
          bestCandidate = input;
        }
      }

      if (bestCandidate && highestScore > 0) {
        return bestCandidate;
      }
    }

    const inputs = Array.from(document.querySelectorAll('input'));
    const pwIndex = inputs.indexOf(passwordInput);
    if (pwIndex > 0) {
      for (let i = pwIndex - 1; i >= Math.max(0, pwIndex - 2); i--) {
        const input = inputs[i];
        const type = (input.getAttribute('type') || 'text').toLowerCase();
        if (['text', 'email'].includes(type)) {
          return input;
        }
      }
    }

    return null;
  }

  const activeHelpers = new Map();

  class PasswordHelper {
    constructor(input) {
      this.input = input;
      this.isOpen = false;
      this.createElements();
      this.reposition();
      this.setupEventListeners();
      this.loadSavedSettings();
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

      // Create Shadow Root for isolation (closed mode for security)
      this.shadow = this.container.attachShadow({ mode: 'closed' });

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
          background: transparent;
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
          overflow: hidden;
        }

        .icon-btn:hover {
          transform: scale(1.1);
          box-shadow: 0 3px 8px rgba(16, 185, 129, 0.4);
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

        .label-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .shortcut-badge {
          background: #1c1c1f;
          color: #71717a;
          border-radius: 4px;
          padding: 1px 4px;
          font-size: 9px;
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
          border: 1px solid #2d2d31;
          pointer-events: none;
          letter-spacing: 0.02em;
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

        .password-wrapper {
          position: relative;
          width: 100%;
        }

        .password-wrapper input {
          padding-right: 32px !important;
        }

        .toggle-password-btn {
          position: absolute;
          right: 8px;
          top: 50%;
          transform: translateY(-50%);
          background: none;
          border: none;
          padding: 0;
          margin: 0;
          color: #9ca3af;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          outline: none;
          pointer-events: auto;
          transition: color 0.15s ease;
        }

        .toggle-password-btn:hover {
          color: #ffffff;
        }
      `;

      // Float Trigger Button
      this.iconBtn = document.createElement('button');
      this.iconBtn.className = 'icon-btn';
      this.iconBtn.setAttribute('title', 'Better LessPass (Alt+L)');
      this.iconBtn.innerHTML = `
        <svg viewBox="0 0 119 119" width="100%" height="100%">
          <g>
            <rect id="bg" y="0" width="119" height="119" fill="#10b981"/>
            <path id="shadow" d="m75.37 22.26v27.46l-10.54 8.559-11.24 45.27 15.42 15.42h49.95v-53.11z" fill="#059669"/>
            <path id="key" d="m37.47 37.46c0 10.06 6.861 18.58 16.12 21.17v44.91h17.97v-10.46h-6.196v-3.793h6.196v-10.46h-6.196v-20.19c9.264-2.593 16.12-11.11 16.12-21.17 0-12.1-9.97-22.41-22.38-22.12s-21.65 10.39-21.65 22.12zm22.03-13.4c7.437 0 13.34 5.963 13.34 13.4 0 7.437-5.903 13.34-13.34 13.34-7.437 0-13.37-5.903-13.37-13.34 0-7.437 5.932-13.4 13.37-13.4z" fill="#fff"/>
          </g>
        </svg>
      `;

      // Get Default Hostname
      const defaultSite = getRegisteredDomain(window.location.hostname);

      // Create Popover Layout matching the screenshot precisely
      this.popover = document.createElement('div');
      this.popover.className = 'popover';
      this.popover.innerHTML = `
        <div class="popover-header">
          <div style="width: 14px; height: 14px; border-radius: 50%; overflow: hidden; display: inline-flex; margin-right: 6px; flex-shrink: 0;">
            <svg viewBox="0 0 119 119" width="14" height="14">
              <g>
                <rect id="bg" y="0" width="119" height="119" fill="#10b981"/>
                <path id="shadow" d="m75.37 22.26v27.46l-10.54 8.559-11.24 45.27 15.42 15.42h49.95v-53.11z" fill="#059669"/>
                <path id="key" d="m37.47 37.46c0 10.06 6.861 18.58 16.12 21.17v44.91h17.97v-10.46h-6.196v-3.793h6.196v-10.46h-6.196v-20.19c9.264-2.593 16.12-11.11 16.12-21.17 0-12.1-9.97-22.41-22.38-22.12s-21.65 10.39-21.65 22.12zm22.03-13.4c7.437 0 13.34 5.963 13.34 13.4 0 7.437-5.903 13.34-13.34 13.34-7.437 0-13.37-5.903-13.37-13.34 0-7.437 5.932-13.4 13.37-13.4z" fill="#fff"/>
              </g>
            </svg>
          </div>
          Better LessPass
          <span class="shortcut-badge" style="margin-left: auto;">Esc</span>
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
          <div class="label-row">
            <label>Master password</label>
            <span class="shortcut-badge">Alt + V</span>
          </div>
          <div class="password-wrapper">
            <input type="password" id="lp-master-password" placeholder="master password">
            <button type="button" class="toggle-password-btn" title="Show password">
              <svg style="width: 16px; height: 14px; fill: currentColor;" viewBox="0 0 24 24">
                <path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/>
              </svg>
            </button>
          </div>
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
          <span class="shortcut-badge" style="background: rgba(255,255,255,0.1); color: #e4e4e7; border-color: rgba(255,255,255,0.15); margin-left: 6px;">Enter</span>
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

      const eyeBtn = this.popover.querySelector('.toggle-password-btn');
      const masterInput = this.popover.querySelector('#lp-master-password');
      if (eyeBtn && masterInput) {
        eyeBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          e.preventDefault();
          this.toggleMasterPasswordVisibility();
        });
      }

      // 1. Contextual Keyboard Shortcut: Toggle popover from host input with Alt+L
      this.input.addEventListener('keydown', (e) => {
        if (e.altKey && (e.key === 'l' || e.key === 'L')) {
          e.preventDefault();
          e.stopPropagation();
          this.togglePopover();
        }
      });

      // 2. Keyboard Shortcuts inside Popover
      this.popover.addEventListener('keydown', (e) => {
        // Escape closes popover
        if (e.key === 'Escape') {
          e.preventDefault();
          e.stopPropagation();
          this.togglePopover();
          this.input.focus(); // return focus to main field
        }

        // Enter generates & fills
        if (e.key === 'Enter') {
          // Avoid firing when focused on checkboxes or buttons (let space/click fire standard actions there)
          if (document.activeElement && (document.activeElement.tagName === 'BUTTON' || document.activeElement.type === 'checkbox')) {
            return;
          }
          e.preventDefault();
          e.stopPropagation();
          this.generateAndFill();
        }

        // Alt + V toggles master password peek/visibility
        if (e.altKey && (e.key === 'v' || e.key === 'V')) {
          e.preventDefault();
          e.stopPropagation();
          this.toggleMasterPasswordVisibility();
        }

        // Focus Trapping: Prevent tab key from leaking focus out of the Shadow DOM
        if (e.key === 'Tab') {
          const focusable = this.getFocusableElements();
          if (focusable.length === 0) return;

          const first = focusable[0];
          const last = focusable[focusable.length - 1];
          const active = this.shadow.activeElement;

          if (e.shiftKey) {
            // Shift + Tab: Wrap from first to last focusable element
            if (active === first || !focusable.includes(active)) {
              e.preventDefault();
              last.focus();
            }
          } else {
            // Tab: Wrap from last to first focusable element
            if (active === last || !focusable.includes(active)) {
              e.preventDefault();
              first.focus();
            }
          }
        }
      });

      // 3. Settings Persistence: Save settings on change
      const optSelectors = [
        '#lp-opt-lowercase',
        '#lp-opt-uppercase',
        '#lp-opt-digits',
        '#lp-opt-symbols',
        '#lp-length',
        '#lp-counter'
      ];
      optSelectors.forEach(selector => {
        const el = this.popover.querySelector(selector);
        if (el) {
          el.addEventListener('change', () => this.saveSettings());
          if (el.tagName === 'INPUT' && el.type === 'number') {
            el.addEventListener('input', () => this.saveSettings());
          }
        }
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

        // Bidirectional sync: prepopulate login from page if username field is filled
        const usernameField = findUsernameField(this.input);
        const loginInput = this.popover.querySelector('#lp-login');
        if (usernameField && usernameField.value && loginInput) {
          loginInput.value = usernameField.value;
        }
        
        // Auto focus the master password field for speed
        setTimeout(() => {
          const masterInput = this.popover.querySelector('#lp-master-password');
          if (masterInput) masterInput.focus();
        }, 50);
      } else {
        this.iconBtn.classList.remove('open');
        this.popover.classList.remove('visible');

        // Reset master password visibility on close for security
        const mInput = this.popover.querySelector('#lp-master-password');
        const eBtn = this.popover.querySelector('.toggle-password-btn');
        if (mInput && eBtn) {
          mInput.setAttribute('type', 'password');
          eBtn.setAttribute('title', 'Show password');
          eBtn.innerHTML = `
            <svg style="width: 16px; height: 14px; fill: currentColor;" viewBox="0 0 24 24">
              <path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/>
            </svg>
          `;
        }
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

        // Securely cache the master password in background in-memory storage via secure message passing
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({ action: 'saveMasterPassword', value: masterPassword });
        }
        const usernameField = findUsernameField(this.input);
        if (usernameField && login) {
          usernameField.value = login;
          usernameField.dispatchEvent(new Event('input', { bubbles: true }));
          usernameField.dispatchEvent(new Event('change', { bubbles: true }));

          // Success glow feedback on username input
          const uTransition = usernameField.style.transition;
          const uOutline = usernameField.style.outline;
          usernameField.style.transition = 'outline 0.2s ease, box-shadow 0.2s ease';
          usernameField.style.outline = '2px solid #10b981';
          usernameField.style.boxShadow = '0 0 8px rgba(16, 185, 129, 0.4)';
          setTimeout(() => {
            usernameField.style.outline = uOutline;
            usernameField.style.boxShadow = '';
            setTimeout(() => {
              usernameField.style.transition = uTransition;
            }, 200);
          }, 800);
        }

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

    toggleMasterPasswordVisibility() {
      const masterInput = this.popover.querySelector('#lp-master-password');
      const eyeBtn = this.popover.querySelector('.toggle-password-btn');
      if (!masterInput || !eyeBtn) return;
      
      const isPassword = masterInput.getAttribute('type') === 'password';
      const type = isPassword ? 'text' : 'password';
      masterInput.setAttribute('type', type);
      
      if (isPassword) {
        eyeBtn.setAttribute('title', 'Hide password');
        eyeBtn.innerHTML = `
          <svg style="width: 16px; height: 14px; fill: currentColor;" viewBox="0 0 24 24">
            <path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.25 1.24-.65 1.69l1.45 1.45C18.8 14.14 19 13.1 19 12c0-4.39-4.27-7.5-9-7.5-1.12 0-2.18.17-3.16.48l1.47 1.47c.83-.28 1.7-.45 2.69-.45zM3 4.27l2.28 2.28C3.5 8.13 2.1 9.92 1.5 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l2.85 2.85 1.27-1.27L4.27 3 3 4.27zM9.54 9.54l1.69 1.69c-.14.4-.23.83-.23 1.27 0 1.93 1.57 3.5 3.5 3.5.44 0 .87-.09 1.27-.23l1.69 1.69c-.83.48-1.85.77-2.96.77-3.31 0-6-2.69-6-6 0-1.11.29-2.13.77-2.96z"/>
          </svg>
        `;
      } else {
        eyeBtn.setAttribute('title', 'Show password');
        eyeBtn.innerHTML = `
          <svg style="width: 16px; height: 14px; fill: currentColor;" viewBox="0 0 24 24">
            <path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/>
          </svg>
        `;
      }
    }

    getFocusableElements() {
      return Array.from(this.shadow.querySelectorAll(
        'input, button, [tabindex="0"]'
      )).filter(el => {
        return el.tabIndex !== -1 && !el.disabled && el.style.display !== 'none';
      });
    }
    loadSavedSettings() {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['lpOpts', 'lpLength', 'lpCounter'], (items) => {
          if (items.lpOpts) {
            this.popover.querySelector('#lp-opt-lowercase').checked = !!items.lpOpts.lowercase;
            this.popover.querySelector('#lp-opt-uppercase').checked = !!items.lpOpts.uppercase;
            this.popover.querySelector('#lp-opt-digits').checked = !!items.lpOpts.digits;
            this.popover.querySelector('#lp-opt-symbols').checked = !!items.lpOpts.symbols;
          }
          if (items.lpLength) {
            this.popover.querySelector('#lp-length').value = items.lpLength;
          }
          if (items.lpCounter) {
            this.popover.querySelector('#lp-counter').value = items.lpCounter;
          }
        });
      }

      // Load securely cached master password from extension background in-memory storage via message passing
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ action: 'loadMasterPassword' }, (response) => {
          if (response && response.success && response.value) {
            const masterInput = this.popover.querySelector('#lp-master-password');
            if (masterInput) {
              masterInput.value = response.value;
            }
          }
        });
      }
    }

    saveSettings() {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        const opts = {
          lowercase: this.popover.querySelector('#lp-opt-lowercase').checked,
          uppercase: this.popover.querySelector('#lp-opt-uppercase').checked,
          digits: this.popover.querySelector('#lp-opt-digits').checked,
          symbols: this.popover.querySelector('#lp-opt-symbols').checked
        };
        const length = parseInt(this.popover.querySelector('#lp-length').value, 10) || 16;
        const counter = parseInt(this.popover.querySelector('#lp-counter').value, 10) || 1;

        chrome.storage.local.set({
          lpOpts: opts,
          lpLength: length,
          lpCounter: counter
        });
      }
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
