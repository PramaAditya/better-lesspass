// Set access level so that content scripts can access chrome.storage.session directly
chrome.runtime.onInstalled.addListener(() => {
  if (chrome.storage && chrome.storage.session) {
    chrome.storage.session.setAccessLevel({
      accessLevel: 'TRUSTED_AND_UNTRUSTED_CONTEXTS'
    }).catch(err => console.error("Error setting session storage access level:", err));
  }
});

chrome.runtime.onStartup.addListener(() => {
  if (chrome.storage && chrome.storage.session) {
    chrome.storage.session.setAccessLevel({
      accessLevel: 'TRUSTED_AND_UNTRUSTED_CONTEXTS'
    }).catch(err => console.error("Error setting session storage access level:", err));
  }
});
