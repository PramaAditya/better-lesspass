<p align="center">
  <img src="icon-128.png" width="96" height="96" alt="Better LessPass Logo">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/manifest-v3-blue.svg?style=flat-square" alt="Manifest V3">
  <img src="https://img.shields.io/badge/algorithm-LessPass%20v2-emerald.svg?style=flat-square" alt="LessPass v2">
  <img src="https://img.shields.io/badge/sync-bidirectional-blueviolet.svg?style=flat-square" alt="Bidirectional Sync">
  <img src="https://img.shields.io/badge/license-GPL--3.0-lightgrey.svg?style=flat-square" alt="GPL-3.0 License">
</p>

# Better LessPass

<p align="center">
  <b>Better LessPass is a modern, stateless password generator Chrome extension that brings premium UX, smart TLD extraction, and bidirectional sync to the classic LessPass algorithm.</b>
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

## Why Better LessPass?

Standard LessPass is stateless but suffers from friction. Better LessPass fixes the UX gap:

*   **Smart TLD Extraction**: Automatically strips subdomains and nested domains (e.g., `xxx.yyy.zzz.com` -> `zzz.com`) while preserving two-part ccTLDs like `.co.uk` and `.edu.sg`.
*   **Two-Way Login Sync**: If you've already filled your email/username on the page, the extension automatically grabs it. If not, filling it in the extension writes it back to the page alongside your generated password.
*   **Shadow DOM Isolation**: The popover injected into pages is encapsulated in a Shadow Root, making it immune to page CSS pollution or style breaking.
*   **Interactive Peek**: Securely toggle visibility on your Master Password; automatically relocks to hidden when closing the popover.

---
<br>

## Head-to-Head Comparison

| Capability / Feature | Better LessPass | Standard LessPass | Traditional Vaults (Bitwarden / 1Pass) |
|:---|:---:|:---:|:---:|
| **Zero Vault / Stateless** | ✅ **Yes** | ✅ Yes | ✗ No (Requires cloud DB sync) |
| **Smart TLD Prepopulation** | ✅ **Yes** | ✗ No (Requires manual input) | ✗ No (Fills from vault entry) |
| **Bidirectional Login Sync** | ✅ **Yes** | ✗ No | ✗ No (Fills password only) |
| **Shadow DOM Encapsulation** | ✅ **Yes** | ✗ No (Uses standard iframe/popup) | ✗ No (Browser standard popup) |
| **Visual Glow Feedback** | ✅ **Yes** | ✗ No | ✗ No |

---
<br>

## Minimum Viable Knowledge

*   ✓ **Zero-Vault Security**: Your master password is never stored, logged, or transmitted. Computation is 100% local.
*   ✓ **Deterministic Keys**: Given the same Site, Login, Master Password, and Complexity Options, the generated output is mathematically guaranteed to be identical on any device.
*   ✓ **No-Sync Freedom**: Access your credentials on any computer simply by running the LessPass algorithm—no vault migration required.
*   ✓ **Auto-Lock Safety**: Peeking your master password automatically resets to hidden (`type="password"`) on popover close to prevent visual snooping.

---
<br>

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/PramaAditya/better-lesspass.git
```

### Loading the Extension:
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** in the top-right corner.
3. Click **Load unpacked** in the top-left corner.
4. Select the cloned `better-lesspass/` directory.
5. Open `test.html` in your browser to verify password-field detection and auto-population!

---
<br>

## Architecture Panoramic

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
