<p align="center">
  <img src="icon-128.png" width="96" height="96" alt="Better LessPass Logo">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/manifest-v3-blue.svg?style=flat-square" alt="Manifest V3">
  <img src="https://img.shields.io/badge/permissions-none-emerald.svg?style=flat-square" alt="No Permissions Required">
  <img src="https://img.shields.io/badge/algorithm-LessPass%20v2-blueviolet.svg?style=flat-square" alt="LessPass v2">
  <img src="https://img.shields.io/badge/license-GPL--3.0-lightgrey.svg?style=flat-square" alt="GPL-3.0 License">
</p>

# Better LessPass

<p align="center">
  <b>Better LessPass is a secure, stateless password generator Chrome extension bringing premium UX, smart TLD extraction, and zero-permission security to the classic LessPass algorithm.</b>
  <br>
  Generate strong, reproducible passwords locally on-the-fly using Web Crypto PBKDF2-SHA256, entirely eliminating the need for cloud vaults, database synchronization, or subscription fees.
</p>

---

<p align="center">
  <b>POPUP INTERFACE PREVIEW</b>
</p>

```text
  +-----------------------------------------------+
  |  Better LessPass                              |
  +-----------------------------------------------+
  |  Site:      [ github.com                   ]  |  <-- Smart TLD auto-extraction
  |  Login:     [ contact@prama.dev            ]  |  <-- Two-way autocomplete sync
  |  Master pw: [ •••••••••••••••••••••     👁 ]  |  <-- Secure peek/unpeek toggle
  +-----------------------------------------------+
  |  Options:  [x] a-z  [x] A-Z  [x] 0-9  [x] %!@  |
  |  Length:   [ 16 ]     Counter: [ 1 ]          |
  +-----------------------------------------------+
  |  [               Generate & Fill           ]  |  <-- Flashes green on success
  +-----------------------------------------------+
```

---
<br>

## LessPass, but without the friction

Standard LessPass is stateless but suffers from UX friction. Better LessPass bridges the gap:

*   **Smart TLD Extraction**: Automatically strips subdomains and subpaths (e.g., `app.sub.github.com` to `github.com`) while preserving multi-part country code TLDs like `.co.uk` and `.edu.sg`.
*   **Two-Way Login Sync**: Autofills username from the active webpage directly into the extension, or pushes a new username typed in the extension back to the form.
*   **Shadow DOM Isolation**: The popover is encapsulated in a Shadow Root, shielding the helper from page CSS pollution and preventing site styles from breaking the extension UI.
*   **Interactive Peek**: Securely toggle visibility on your Master Password; automatically relocks to hidden when closing the popover to prevent visual snooping.

---
<br>

## Traditional Vaults vs. Better LessPass

| Feature | Better LessPass | Standard LessPass | Traditional Vaults (e.g., Bitwarden) |
|:---|:---:|:---:|:---:|
| **Stateless & Local** | ✅ **Yes** (Zero storage) | ✅ Yes | ✗ No (Requires DB sync / cloud login) |
| **Zero Permissions** | ✅ **Yes** (`"permissions": []`) | ✗ No | ✗ No (Requires tabs, network, storage) |
| **Smart TLD Prepopulation**| ✅ **Yes** (Automatic) | ✗ No | ✗ No (Manual entry lookup) |
| **Bidirectional Sync** | ✅ **Yes** | ✗ No | ✗ No (One-way autofill) |
| **Shadow DOM Popover** | ✅ **Yes** (Isolated CSS) | ✗ No | ✗ No (Browser extension standard popup) |

---
<br>

## Minimum Viable Knowledge

*   ✓ **Zero-Vault Security**: Your master password is never saved, cached, or transmitted. Key derivation runs 100% on the client.
*   ✓ **Deterministic Keys**: Given the same Site, Login, Master Password, and Complexity Options, the generated output is mathematically identical on any device.
*   ✓ **Zero Permission Footprint**: By requiring empty Manifest V3 permissions, the extension guarantees that your inputs cannot be exfiltrated.
*   ✓ **Auto-Lock Safety**: Peeking your master password automatically resets to hidden (`type="password"`) on popover close to prevent visual snooping.

---
<br>

## Quick Start

```bash
# Clone the repository
git clone https://github.com/PramaAditya/better-lesspass.git
```

### Loading the Extension:
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** in the top-right corner.
3. Click **Load unpacked** in the top-left corner.
4. Select the cloned `better-lesspass/` directory.
5. Open `test.html` in your browser to test field detection and auto-population!

---
<br>

## System Architecture

```text
  Active Webpage           Shadow DOM Popover            Crypto Engine (Web Crypto)
 ─────────────────        ────────────────────          ────────────────────────────
  [Password Input] ───→   [Injected Helper Icon]
                                  │
                                  ▼
  [Autofill Form]  ←───   [Generate & Fill]  ◄───   PBKDF2-SHA256 (100k Iterations)
  (Two-way sync)               (Fills Inputs)                     │
                                                                  ▼
                                                      Deterministic BigInt division
```

---
<br>

<p align="center">
  <a href="https://github.com/PramaAditya/better-lesspass/issues">Report Bug</a> · 
  <a href="https://github.com/lesspass/lesspass">Original LessPass</a>
</p>

<p align="center">
  <sub>Licensed under the <a href="LICENSE">GPL-3.0 License</a>. Re-implementation by Prama Aditya.</sub>
</p>
