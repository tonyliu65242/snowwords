// content.js – fixed: double right-click using word-under-cursor detection + original-style notifications + large popup + keybind repeat fix

const SNOWWORDS_DOMAIN = 'https://snowwords.me/';

/**
 * Inject notification + popup CSS
 */
function injectStyles() {
  if (document.getElementById('sw-styles')) return;
  const style = document.createElement('style');
  style.id = 'sw-styles';
  style.textContent = `
    /* Notification (original style) */
    .sw-notification {
      position: fixed;
      right: 20px;
      padding: 16px 20px;
      border-radius: 12px;
      font-size: 14px;
      font-weight: 500;
      z-index: 2147483647;
      font-family: 'Segoe UI', sans-serif;
      box-shadow: 0 4px 20px rgba(0,0,0,0.3);
      max-width: 320px;
      word-wrap: break-word;
      animation: slideInRight 0.3s ease;
      border-left: 4px solid;
    }
    .sw-notification.info    { background: #e3f2fd; color: #1976d2; border-left-color: #2196f3; }
    .sw-notification.success { background: #e8f5e8; color: #2e7d32; border-left-color: #4caf50; }
    .sw-notification.error   { background: #ffebee; color: #d32f2f; border-left-color: #f44336; }
    .sw-notification.warning { background: #fff3e0; color: #f57c00; border-left-color: #ff9800; }
    @keyframes slideInRight {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }

    /* Large center popup */
    .sw-popup-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background: rgba(0,0,0,0.6);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 2147483647;
    }
    .sw-popup {
      background: #ffffff;
      border-radius: 12px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.2);
      max-width: 500px;
      width: 90%;
      padding: 24px;
      font-family: 'Segoe UI', sans-serif;
      animation: popIn 0.3s ease-out;
    }
    .sw-popup h2 {
      margin: 0 0 12px;
      font-size: 22px;
      color: #2c3e50;
    }
    .sw-popup p {
      font-size: 16px;
      color: #555;
      line-height: 1.4;
      margin-bottom: 20px;
    }
    .sw-popup button {
      background: #388e3c;
      color: #fff;
      border: none;
      padding: 10px 20px;
      border-radius: 6px;
      font-size: 15px;
      cursor: pointer;
    }
    @keyframes popIn {
      from { transform: scale(0.9); opacity: 0; }
      to   { transform: scale(1);   opacity: 1; }
    }
  `;
  document.head.appendChild(style);
}

/**
 * Show a notification in the top-right
 */
function showNotification(message, type = 'info', duration = 4000) {
  const notif = document.createElement('div');
  notif.className = `sw-notification ${type}`;
  notif.textContent = message;
  document.body.appendChild(notif);
  const notifs = document.querySelectorAll('.sw-notification');
  notifs.forEach((el, idx) => el.style.top = `${20 + idx * 80}px`);
  setTimeout(() => {
    notif.style.animation = 'slideInRight 0.3s ease reverse';
    setTimeout(() => notif.remove(), 300);
  }, duration);
}

/**
 * Show large centered popup
 */
function showLargePopup(word, definition) {
  document.getElementById('sw-popup-overlay')?.remove();
  const overlay = document.createElement('div');
  overlay.id = 'sw-popup-overlay';
  overlay.className = 'sw-popup-overlay';
  overlay.innerHTML = `
    <div class="sw-popup">
      <h2>✅ Word Added!</h2>
      <p><strong>${word}</strong><br>${definition}</p>
      <div style="text-align:right;"><button id="sw-popup-close">Continue</button></div>
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.querySelector('#sw-popup-close').addEventListener('click', () => overlay.remove());
}

/**
 * Get word under cursor using range methods
 */
function getWordUnderCursor(x, y) {
  let range;
  if (document.caretPositionFromPoint) {
    const pos = document.caretPositionFromPoint(x, y);
    if (!pos) return '';
    range = document.createRange();
    range.setStart(pos.offsetNode, pos.offset);
    range.setEnd(pos.offsetNode, pos.offset);
  } else if (document.caretRangeFromPoint) {
    range = document.caretRangeFromPoint(x, y);
  } else {
    return '';
  }
  const node = range.startContainer;
  if (!node || node.nodeType !== Node.TEXT_NODE) return '';
  const text = node.textContent;
  let idx = range.startOffset;
  let start = idx, end = idx;
  while (start > 0 && /[A-Za-z]/.test(text[start - 1])) start--;
  while (end < text.length && /[A-Za-z]/.test(text[end])) end++;
  return text.slice(start, end).trim();
}

let lastRightTime = 0;
let lastRightWord = '';

/**
 * Initialize extension: styles + listeners + ready notification
 */
function initExtension() {
  injectStyles();
  setupListeners();
  chrome.runtime.sendMessage({ action: 'checkAuthStatus' }, resp => {
    if (resp.authenticated) {
      showNotification('✅ Snowwords ready! Double‑right‑click a word to add.', 'success');
    }
  });
}

/**
 * Track double right-click on same word under cursor
 */
function setupListeners() {
  document.addEventListener('contextmenu', e => {
    e.preventDefault();
    const now = Date.now();
    const word = getWordUnderCursor(e.clientX, e.clientY);
    if (word && now - lastRightTime < 500 && word === lastRightWord) {
      addWord(word);
    }
    lastRightTime = now;
    lastRightWord = word;
  });

  document.addEventListener('keydown', e => {
    if (e.repeat) return;  // prevent repeat firing
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'a') {
      e.preventDefault();
      const sel = window.getSelection().toString().trim();
      if (sel) addWord(sel);
      else showNotification('Select some text first!', 'error');
    }
  });
}

/**
 * Send word to background, handle wake/auth/CSRF
 */
async function addWord(word) {
  showNotification(`Adding "${word}"…`, 'info');
  try {
    const resp = await new Promise((res, rej) => {
      const t = setTimeout(() => rej('timeout'), 15000);
      chrome.runtime.sendMessage({ action: 'addWordToVocabulary', word }, r => {
        clearTimeout(t);
        if (chrome.runtime.lastError) rej(chrome.runtime.lastError.message);
        else res(r);
      });
    });
    if (resp.wakingUp) {
      showNotification('⚡️ Waking up server, try again shortly', 'info');
      return;
    }
    if (resp.notAuthenticated) {
      showNotification('🔐 Please log in to Snowwords', 'error');
      return;
    }
    if (resp.success) {
      showLargePopup(word, resp.definition);
      return;
    }
    if (resp.alreadyExists) {
      showNotification(`⚠️ "${word}" is already in your vocabulary`, 'warning');
      return;
    }
    showNotification(`❌ ${resp.error}`, 'error');
  } catch (err) {
    showNotification(err === 'timeout' ? '⏱️ Server took too long' : `❌ ${err}`, 'error');
  }
}

// Run on page load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initExtension);
} else {
  initExtension();
}
