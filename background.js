// Background Service Worker for AI Context Guard

class BackgroundService {
  constructor() {
    this.init();
  }

  init() {
    this.setupListeners();
    this.setupAlarm();
    this.initializeStorage();
  }

  initializeStorage() {
    chrome.storage.local.get(['acgConfig', 'acgEvents'], (result) => {
      if (!result.acgConfig) {
        chrome.storage.local.set({
          acgConfig: {
            enableWarnings: true,
            enableAutoRedact: true,
            enableLogging: true,
            scanDelay: 300
          }
        });
      }

      if (!result.acgEvents) {
        chrome.storage.local.set({ acgEvents: [] });
      }
    });
  }

  setupListeners() {
    // Listen for messages from content scripts
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.type === 'LOG_EVENT') {
        this.logEvent(request.event, sender);
        sendResponse({ success: true });
      } else if (request.type === 'GET_CONFIG') {
        chrome.storage.local.get('acgConfig', (result) => {
          sendResponse(result.acgConfig || {});
        });
      }
      return true; // Keep channel open for async response
    });

    // Listen for tab updates to inject content script
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'complete') {
        this.injectContentScript(tabId, tab.url);
      }
    });

    // Listen for storage changes
    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName === 'local' && changes.acgConfig) {
        this.broadcastConfigUpdate(changes.acgConfig.newValue);
      }
    });
  }

  injectContentScript(tabId, url) {
    if (!this.isAIWebsite(url)) return;

    chrome.scripting.executeScript(
      {
        target: { tabId },
        files: ['content.js']
      },
      () => {
        if (chrome.runtime.lastError) {
          console.debug('ACG: Could not inject script (already injected or blocked)', chrome.runtime.lastError);
        }
      }
    );
  }

  isAIWebsite(url) {
    const aiDomains = [
      'chatgpt.com',
      'chat.openai.com',
      'gemini.google.com',
      'copilot.microsoft.com',
      'claude.ai',
      'bard.google.com'
    ];
    return aiDomains.some(domain => url && url.includes(domain));
  }

  logEvent(event, sender) {
    chrome.storage.local.get('acgEvents', (result) => {
      const events = result.acgEvents || [];
      const enrichedEvent = {
        ...event,
        tabId: sender.tab?.id,
        tabTitle: sender.tab?.title,
        tabUrl: sender.tab?.url
      };

      events.push(enrichedEvent);
      // Keep only last 5000 events
      events.splice(0, Math.max(0, events.length - 5000));

      chrome.storage.local.set({ acgEvents: events }, () => {
        // Aggregate stats for analytics if needed
        this.updateMetrics(enrichedEvent);
      });
    });
  }

  updateMetrics(event) {
    const today = new Date().toISOString().split('T')[0];
    const metricsKey = `metrics:${today}`;

    chrome.storage.local.get(metricsKey, (result) => {
      const metrics = result[metricsKey] || {
        date: today,
        totalFindings: 0,
        criticalBlocks: 0,
        highRiskBlocks: 0,
        redactionCount: 0,
        cancelledCount: 0,
        forcedCount: 0
      };

      metrics.totalFindings += event.findingsCount || 0;
      metrics.criticalBlocks += event.critical || 0;
      metrics.highRiskBlocks += event.high || 0;

      if (event.action === 'redacted') metrics.redactionCount += 1;
      if (event.action === 'cancelled') metrics.cancelledCount += 1;
      if (event.action === 'forced') metrics.forcedCount += 1;

      chrome.storage.local.set({ [metricsKey]: metrics });
    });
  }

  broadcastConfigUpdate(config) {
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach(tab => {
        if (this.isAIWebsite(tab.url)) {
          chrome.tabs.sendMessage(tab.id, {
            type: 'CONFIG_UPDATE',
            config
          }).catch(() => {});
        }
      });
    });
  }

  setupAlarm() {
    // Clean up old events daily
    chrome.alarms.create('cleanup_old_events', { periodInMinutes: 24 * 60 });

    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === 'cleanup_old_events') {
        this.cleanupOldEvents();
      }
    });
  }

  cleanupOldEvents() {
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    chrome.storage.local.get('acgEvents', (result) => {
      const events = result.acgEvents || [];
      const filtered = events.filter(event => {
        const eventDate = new Date(event.timestamp);
        return eventDate > sevenDaysAgo;
      });

      chrome.storage.local.set({ acgEvents: filtered });
    });
  }
}

// Initialize background service
new BackgroundService();

// Handle extension icon click
chrome.action.onClicked.addListener((tab) => {
  chrome.runtime.openOptionsPage();
});
