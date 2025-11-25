// Popup script for AI Context Guard

class PopupManager {
  constructor() {
    this.stats = {
      critical: 0,
      high: 0,
      redacted: 0,
      events: 0
    };
    this.recentEvents = [];
    this.init();
  }

  init() {
    this.loadStats();
    this.setupEventListeners();
    this.setupToggleSync();
    this.startAutoRefresh();
  }

  loadStats() {
    chrome.storage.local.get(['acgEvents', 'acgConfig'], (result) => {
      const events = result.acgEvents || [];
      const config = result.acgConfig || {};

      this.recentEvents = events.slice(-10).reverse();

      // Calculate stats
      let criticalCount = 0;
      let highCount = 0;
      let redactedCount = 0;

      const today = new Date();
      today.setHours(0, 0, 0, 0);

      events.forEach(event => {
        const eventDate = new Date(event.timestamp);
        eventDate.setHours(0, 0, 0, 0);

        if (eventDate.getTime() === today.getTime()) {
          criticalCount += event.critical || 0;
          highCount += event.high || 0;
          if (event.action === 'redacted') {
            redactedCount += 1;
          }
        }
      });

      this.stats = {
        critical: criticalCount,
        high: highCount,
        redacted: redactedCount,
        events: events.length
      };

      this.updateDisplay();
      this.updateConfig(config);
    });
  }

  updateDisplay() {
    document.getElementById('criticalCount').textContent = this.stats.critical;
    document.getElementById('highCount').textContent = this.stats.high;
    document.getElementById('redactedCount').textContent = this.stats.redacted;
    document.getElementById('eventsCount').textContent = this.stats.events;

    this.updateEventsList();
  }

  updateEventsList() {
    const eventsList = document.getElementById('eventsList');

    if (this.recentEvents.length === 0) {
      eventsList.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">📋</div>
          <div class="empty-state-text">No events yet</div>
        </div>
      `;
      return;
    }

    eventsList.innerHTML = this.recentEvents.map(event => {
      const actionClass = event.action.replace(/_/g, '-');
      const time = new Date(event.timestamp);
      const timeStr = time.toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit',
        second: '2-digit'
      });

      const typesStr = event.types.slice(0, 2).join(', ') + 
        (event.types.length > 2 ? ` +${event.types.length - 2}` : '');

      return `
        <div class="event-item">
          <span class="event-action ${actionClass}">${event.action.toUpperCase()}</span>
          <br>
          <small>${event.findingsCount} issues found (${event.critical} critical)</small>
          <br>
          <small style="color: #d1d5db;">${typesStr}</small>
          <span class="event-time">${timeStr}</span>
        </div>
      `;
    }).join('');
  }

  setupToggleSync() {
    const enableWarnings = document.getElementById('enableWarnings');
    const enableAutoRedact = document.getElementById('enableAutoRedact');
    const enableLogging = document.getElementById('enableLogging');

    // Load current config
    chrome.storage.local.get('acgConfig', (result) => {
      const config = result.acgConfig || {
        enableWarnings: true,
        enableAutoRedact: true,
        enableLogging: true
      };

      enableWarnings.checked = config.enableWarnings;
      enableAutoRedact.checked = config.enableAutoRedact;
      enableLogging.checked = config.enableLogging;
    });

    enableWarnings.addEventListener('change', () => {
      this.saveConfig({ enableWarnings: enableWarnings.checked });
    });

    enableAutoRedact.addEventListener('change', () => {
      this.saveConfig({ enableAutoRedact: enableAutoRedact.checked });
    });

    enableLogging.addEventListener('change', () => {
      this.saveConfig({ enableLogging: enableLogging.checked });
    });
  }

  updateConfig(config) {
    document.getElementById('enableWarnings').checked = config.enableWarnings !== false;
    document.getElementById('enableAutoRedact').checked = config.enableAutoRedact !== false;
    document.getElementById('enableLogging').checked = config.enableLogging !== false;
  }

  saveConfig(updates) {
    chrome.storage.local.get('acgConfig', (result) => {
      const config = result.acgConfig || {
        enableWarnings: true,
        enableAutoRedact: true,
        enableLogging: true
      };

      const newConfig = { ...config, ...updates };
      chrome.storage.local.set({ acgConfig: newConfig });

      // Notify all content scripts of config change
      chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
          chrome.tabs.sendMessage(tab.id, { 
            type: 'CONFIG_UPDATE', 
            config: newConfig 
          }).catch(() => {}); // Ignore errors for non-extension tabs
        });
      });
    });
  }

  setupEventListeners() {
    document.getElementById('clearEventsBtn').addEventListener('click', () => {
      if (confirm('Clear all detection events?')) {
        chrome.storage.local.set({ acgEvents: [] }, () => {
          this.recentEvents = [];
          this.stats.events = 0;
          this.stats.critical = 0;
          this.stats.high = 0;
          this.stats.redacted = 0;
          this.updateDisplay();
        });
      }
    });

    document.getElementById('openSettingsBtn').addEventListener('click', () => {
      chrome.runtime.openOptionsPage();
    });
  }

  startAutoRefresh() {
    // Refresh stats every 2 seconds
    setInterval(() => {
      this.loadStats();
    }, 2000);
  }
}

// Initialize when popup loads
document.addEventListener('DOMContentLoaded', () => {
  new PopupManager();
});
