// background.js – now with server‑wake and auth gating

const SNOWWORDS_DOMAIN = 'https://snowwords.me/';

// ——— Initialization ———
chrome.runtime.onInstalled.addListener(() => {
  console.log('❄️ Snowwords extension installed');
  chrome.contextMenus.create({
    id: 'snowwords-add-word',
    title: '❄️ Add "%s" to Snowwords vocabulary',
    contexts: ['selection']
  });
  chrome.storage.sync.set({
    autoDetect: true,
    showNotifications: true,
    difficultyLevel: 2,
    extensionEnabled: true
  });
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon48.png',
    title: 'Snowwords Extension Ready!',
    message: 'Double‑click any word on webpages to add it to your vocabulary.'
  });
  chrome.alarms.create('hourlyCleanup', { periodInMinutes: 60 });
});

chrome.runtime.onStartup.addListener(() => {
  console.log('❄️ Snowwords extension started');
  chrome.alarms.create('hourlyCleanup', { periodInMinutes: 60 });
});

// ——— UI hooks ———
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'snowwords-add-word' && info.selectionText) {
    chrome.tabs.sendMessage(tab.id, {
      action: 'addSelectedWord',
      word: info.selectionText.trim()
    }).catch(console.error);
  }
});

chrome.action.onClicked.addListener((tab) => {
  chrome.tabs.sendMessage(tab.id, { action: 'addSelectedWord' })
    .catch(() => {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: 'Select some text first',
        message: 'Highlight a word, then click the Snowwords icon.'
      });
    });
});

chrome.commands.onCommand.addListener((command, tab) => {
  if (command === 'add-selected-word') {
    chrome.tabs.sendMessage(tab.id, { action: 'addSelectedWord' }).catch(console.error);
  }
});

// ——— Main router ———
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('🔔 Background received:', request);

  switch (request.action) {
    case 'checkAuthStatus':
      handleCheckAuthStatus(sendResponse);
      return true;

    case 'addWordToVocabulary':
      handleAddWordToVocabulary(request, sendResponse);
      return true;

    case 'getSettings':
      handleGetSettings(sendResponse);
      return true;

    case 'updateSettings':
      handleUpdateSettings(request, sendResponse);
      return true;

    case 'updateBadge':
      handleUpdateBadge(request, sender);
      break;
  }
});

// ——— Alarm cleanup ———
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === 'hourlyCleanup') {
    console.log('🧹 Running hourly cleanup');
    // prune storage or notifications here
  }
});

// ——— Helper: ping auth‑status (wakes server, checks login) ———
async function handleCheckAuthStatus(sendResponse) {
  try {
    const res = await fetch(`${SNOWWORDS_DOMAIN}/api/extension/auth-status`, {
      method: 'GET',
      credentials: 'include'
    });
    // No CSRF needed here
    const json = await res.json();
    sendResponse(json);
  } catch (err) {
    console.error('⚠️ Auth‑status ping failed:', err);
    // server may be sleeping
    sendResponse({ authenticated: false, wakingUp: true });
  }
}

// ——— Helper: fetch CSRF token ———
async function getCSRFToken() {
  const res = await fetch(`${SNOWWORDS_DOMAIN}/api/csrf-token`, {
    method: 'GET',
    credentials: 'include'
  });
  if (!res.ok) throw new Error(`CSRF token fetch failed (${res.status})`);
  const { csrfToken } = await res.json();
  return csrfToken;
}

// ——— Handler: Add word, with wake + auth + CSRF ———
function handleAddWordToVocabulary(request, sendResponse) {
  (async () => {
    try {
      // 1) Wake & auth‑check
      const authRes = await fetch(`${SNOWWORDS_DOMAIN}/api/extension/auth-status`, {
        method: 'GET',
        credentials: 'include'
      });
      const authJson = await authRes.json();
      if (!authRes.ok || authJson.wakingUp) {
        // server is starting up
        return sendResponse({ wakingUp: true });
      }
      if (!authJson.authenticated) {
        // not logged in
        return sendResponse({ notAuthenticated: true });
      }

      // 2) Fetch CSRF token
      const csrfToken = await getCSRFToken();

      // 3) Define the word
      const defRes = await fetch(`${SNOWWORDS_DOMAIN}/api/extension/define-word`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify({ word: request.word })
      });
      const defJson = await defRes.json();
      if (!defRes.ok) {
        return sendResponse({ error: defJson.error || `Define failed (${defRes.status})` });
      }
      if (defJson.alreadyExists) {
        return sendResponse({ alreadyExists: true, definition: defJson.definition });
      }

      // 4) Add the word
      const addRes = await fetch(`${SNOWWORDS_DOMAIN}/api/extension/add-word`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify({
          word: request.word,
          definition: defJson.definition,
          difficultyLevel: 2
        })
      });
      const addJson = await addRes.json();
      if (!addRes.ok) {
        return sendResponse({ error: addJson.error || `Add failed (${addRes.status})` });
      }

      // Success!
      sendResponse({ success: true, definition: defJson.definition });

    } catch (err) {
      console.error('⚠️ addWordToVocabulary error:', err);
      sendResponse({ error: err.message });
    }
  })();
}

// ——— Other handlers (unchanged) ———
function handleGetSettings(sendResponse) {
  chrome.storage.sync.get(
    ['autoDetect','showNotifications','difficultyLevel','extensionEnabled'],
    items => sendResponse(items)
  );
}

function handleUpdateSettings(request, sendResponse) {
  chrome.storage.sync.set(request.settings, () => sendResponse({ success: true }));
}

function handleUpdateBadge(request, sender) {
  if (typeof request.count === 'number') {
    chrome.action.setBadgeText({
      text: String(request.count),
      tabId: sender.tab?.id
    });
  }
}
