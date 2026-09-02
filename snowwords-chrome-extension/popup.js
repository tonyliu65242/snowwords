// popup.js - Extension popup functionality

const SNOWWORDS_DOMAIN = 'https://snowwords.me'; // Change to your domain

// Initialize popup when DOM loads
document.addEventListener('DOMContentLoaded', initializePopup);

async function initializePopup() {
  console.log('Snowwords popup initialized');
  
  // Setup event listeners first
  setupEventListeners();
  
  // Load data
  await checkConnectionStatus();
  await loadUserStats();
}

// Setup all event listeners
function setupEventListeners() {
  // Action buttons
  document.getElementById('select-word-btn').addEventListener('click', activateWordSelection);
  document.getElementById('open-snowwords-btn').addEventListener('click', openSnowwords);
  document.getElementById('practice-btn').addEventListener('click', openPractice);
  document.getElementById('vocab-list-btn').addEventListener('click', openVocabList);
  
  // Footer links
  document.getElementById('help-link').addEventListener('click', openHelp);
  document.getElementById('feedback-link').addEventListener('click', openFeedback);
  document.getElementById('upgrade-link').addEventListener('click', openUpgrade);
}

// Check connection to Snowwords
async function checkConnectionStatus() {
  const statusElement = document.getElementById('connection-status');
  
  try {
    const response = await fetch(`${SNOWWORDS_DOMAIN}/api/extension/auth-status`, {
      method: 'GET',
      credentials: 'include'
    });
    
    if (response.ok) {
      const data = await response.json();
      
      if (data.authenticated) {
        statusElement.className = 'status connected';
        statusElement.innerHTML = `
          <div class="status-indicator"></div>
          <span>Connected as ${data.user.username || data.user.email}</span>
        `;
        
        // Enable action buttons
        enableActionButtons(true);
        
        return true;
      } else {
        throw new Error('Not authenticated');
      }
    } else {
      throw new Error('Connection failed');
    }
  } catch (error) {
    console.error('Connection check failed:', error);
    statusElement.className = 'status disconnected';
    statusElement.innerHTML = `
      <div class="status-indicator"></div>
      <span>Not connected - <a href="#" id="login-link">Login</a></span>
    `;
    
    // Add login link handler
    const loginLink = document.getElementById('login-link');
    if (loginLink) {
      loginLink.onclick = (e) => {
        e.preventDefault();
        chrome.tabs.create({ url: `${SNOWWORDS_DOMAIN}/login` });
        window.close();
      };
    }
    
    // Disable action buttons
    enableActionButtons(false);
    
    return false;
  }
}

// Enable/disable action buttons
function enableActionButtons(enabled) {
  const actionButtons = document.querySelectorAll('.action-btn');
  const statsSection = document.getElementById('stats-section');
  
  actionButtons.forEach(button => {
    button.disabled = !enabled;
    if (enabled) {
      button.classList.remove('disabled');
    } else {
      button.classList.add('disabled');
    }
  });
  
  // Hide stats if not connected
  if (enabled) {
    statsSection.classList.remove('hidden');
  } else {
    statsSection.classList.add('hidden');
  }
}

// Load user statistics
async function loadUserStats() {
  try {
    const response = await fetch(`${SNOWWORDS_DOMAIN}/api/extension/stats`, {
      method: 'GET',
      credentials: 'include'
    });
    
    if (response.ok) {
      const stats = await response.json();
      
      // Update UI with stats
      document.getElementById('total-words').textContent = stats.totalWords || 0;
      document.getElementById('mastered-words').textContent = stats.masteredWords || 0;
      document.getElementById('streak').textContent = stats.currentStreak || 0;
      document.getElementById('this-week').textContent = stats.wordsThisWeek || 0;
      
    } else {
      setDefaultStats();
    }
  } catch (error) {
    console.error('Failed to load stats:', error);
    setDefaultStats();
  }
}

// Set default stats when loading fails
function setDefaultStats() {
  document.getElementById('total-words').textContent = '--';
  document.getElementById('mastered-words').textContent = '--';
  document.getElementById('streak').textContent = '--';
  document.getElementById('this-week').textContent = '--';
}

// Action button handlers
function activateWordSelection() {
  chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
    chrome.tabs.sendMessage(tabs[0].id, {action: 'addSelectedWord'}).catch(() => {
      // If content script not ready, show helpful message
      showNotification('Please select some text on the page first, then try again.');
    });
    window.close();
  });
}

function openSnowwords() {
  chrome.tabs.create({ url: `${SNOWWORDS_DOMAIN}/activities` });
  window.close();
}

function openPractice() {
  chrome.tabs.create({ url: `${SNOWWORDS_DOMAIN}/test` });
  window.close();
}

function openVocabList() {
  chrome.tabs.create({ url: `${SNOWWORDS_DOMAIN}/vocab` });
  window.close();
}

// Footer link handlers
function openHelp(event) {
  event.preventDefault();
  chrome.tabs.create({ url: `${SNOWWORDS_DOMAIN}/help` });
  window.close();
}

function openFeedback(event) {
  event.preventDefault();
  chrome.tabs.create({ url: `${SNOWWORDS_DOMAIN}/feedback` });
  window.close();
}

function openUpgrade(event) {
  event.preventDefault();
  chrome.tabs.create({ url: `${SNOWWORDS_DOMAIN}/subscription/plans` });
  window.close();
}

// Show notification (simple alert for now)
function showNotification(message) {
  // Create a simple notification element
  const notification = document.createElement('div');
  notification.style.cssText = `
    position: fixed;
    top: 10px;
    left: 10px;
    right: 10px;
    background: #4682B4;
    color: white;
    padding: 10px;
    border-radius: 4px;
    font-size: 12px;
    z-index: 1000;
    animation: slideDown 0.3s ease;
  `;
  notification.textContent = message;
  
  document.body.appendChild(notification);
  
  // Remove after 3 seconds
  setTimeout(() => {
    notification.remove();
  }, 3000);
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'statsUpdated') {
    loadUserStats();
  }
  
  if (request.action === 'connectionChanged') {
    checkConnectionStatus();
  }
});

// Refresh data when popup becomes visible
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    checkConnectionStatus();
    loadUserStats();
  }
});

// Add CSS animation for notifications
const style = document.createElement('style');
style.textContent = `
  @keyframes slideDown {
    from {
      transform: translateY(-100%);
      opacity: 0;
    }
    to {
      transform: translateY(0);
      opacity: 1;
    }
  }
`;
document.head.appendChild(style);
