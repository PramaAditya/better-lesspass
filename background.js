// Secure background service worker for Better LessPass
// Keeps chrome.storage.session restricted to TRUSTED_ONLY (extension context only)
// Content scripts communicate securely via isolated message passing.

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'saveMasterPassword') {
    if (chrome.storage && chrome.storage.session) {
      chrome.storage.session.set({ lpMasterPassword: request.value })
        .then(() => sendResponse({ success: true }))
        .catch(err => {
          console.error("Error writing to session storage:", err);
          sendResponse({ success: false, error: err.message });
        });
      return true; // Keep message channel open for async response
    }
  }

  if (request.action === 'loadMasterPassword') {
    if (chrome.storage && chrome.storage.session) {
      chrome.storage.session.get(['lpMasterPassword'])
        .then((items) => sendResponse({ success: true, value: items.lpMasterPassword || null }))
        .catch(err => {
          console.error("Error reading from session storage:", err);
          sendResponse({ success: false, error: err.message });
        });
      return true; // Keep message channel open for async response
    }
  }
});
