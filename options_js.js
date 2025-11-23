// Options page script for AI Context Guard

class OptionsManager {
  constructor() {
    this.detectionTypes = {
      'AWS API Key': 'CRITICAL',
      'AWS Secret': 'CRITICAL',
      'GitHub Token': 'CRITICAL',
      'GitHub PAT': 'CRITICAL',
      'Slack Token': 'CRITICAL',
      'Stripe Key': 'CRITICAL',
      'Private Keys (RSA/SSH)': 'CRITICAL',
      'JWT Token': 'HIGH',
      'API Keys': 'HIGH',
      'Bearer Tokens': 'HIGH',
      'Database Connections': 'CRITICAL',
      'SQL Passwords': 'CRITICAL',
      'Environment Variables': 'HIGH',
      'Social Security Number': 'CRITICAL',
      'Credit Card': 'CRITICAL',
      'IBAN': 'CRITICAL',
      'Medical Record ID': 'CRITICAL',
      'Insurance ID': 'CRITICAL',
      'Internal IP Addresses': 'HIGH',
      'Internal Domains': 'HIGH',
      'Email Addresses': 'MEDIUM',
      'Phone Numbers': 'MEDIUM'
    };

    this.init();
  }

  init() {
    this.setupToggleListeners();
    this.setupSliderListener();
    this.setupButtonListeners();
    this.renderDetectionTypes();
    this.loadSettings();
    this.loadStats();
  }

  loadSettings() {
    chrome.storage.local.get('acgConfig', (result) => {
      const config = result.acgConfig || {
        enableWarnings: true,
        enableAutoRedact: true,
        enableLogging: true,
        scanDelay: 300
      };

      this.updateToggleUI(document.getElementById('enableWarnings'), config.enableWarnings);
      this.updateToggleUI(document.getElementById('enableAutoRedact'), config.enableAutoRedact);
      this.updateToggleUI(document.getElementById('enableLogging'), config.enableLogging);

      document.getElementById('scanDelay').value = config.scanDelay || 300;
      document.getElementById('scanDelayValue').textContent = `${config.scanDelay || 300}ms`;
    });
  }

  loadStats() {
    chrome.storage.local.get(['acgEvents'], (result) => {
      const events = result.acgEvents || [];
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      let todayCount = 0;
      let blockCount = 0;
      let redactCount = 0;

      events.forEach(event => {
        const eventDate = new Date(event.timestamp);
        eventDate.setHours(0, 0, 0, 0);

        if (eventDate.getTime() === today.getTime()) {
          todayCount += 1;
          blockCount += event.critical || 0;
          if (event.action === 'redacted') {
            redactCount += 1;
          }
        }
      });

      const statsGrid = document.querySelector('.stats-grid');
      if (statsGrid) {
        statsGrid.innerHTML = `
          <div class="stat-box">
            <div class="stat-value">${todayCount}</div>
            <div class="stat-label">Events Today</div>
          </div>
          <div class="stat-box">
            <div class="stat-value">${blockCount}</div>
            <div class="stat-label">Critical Blocks</div>
          </div>
          <div class="stat-box">
            <div class="stat-value">${redactCount}</div>
            <div class="stat-label">Redacted</div>
          </div>
        `;
      }
    });
  }

  setupToggleListeners() {
    document.getElementById('enableWarnings').addEventListener('click', (e) => {
      const enabled = !e.target.classList.contains('enabled');
      this.updateToggleUI(e.target, enabled);
      this.saveConfig({ enableWarnings: enabled });
    });

    document.getElementById('enableAutoRedact').addEventListener('click', (e) => {
      const enabled = !e.target.classList.contains('enabled');
      this.updateToggleUI(e.target, enabled);
      this.saveConfig({ enableAutoRedact: enabled });
    });

    document.getElementById('enableLogging').addEventListener('click', (e) => {
      const enabled = !e.target.classList.contains('enabled');
      this.updateToggleUI(e.target, enabled);
      this.saveConfig({ enableLogging: enabled });
    });
  }

  setupSliderListener() {
    const slider = document.getElementById('scanDelay');
    const valueDisplay = document.getElementById('scanDelayValue');

    slider.addEventListener('input', (e) => {
      const value = e.target.value;
      valueDisplay.textContent = `${value}ms`;
      this.saveConfig({ scanDelay: parseInt(value) });
    });
  }

  setupButtonListeners() {
    document.getElementById('clearHistoryBtn').addEventListener('click', () => {
      if (confirm('Are you sure you want to clear all history? This cannot be undone.')) {
        chrome.storage.local.set({ acgEvents: [] }, () => {
          alert('History cleared');
          this.loadStats();
        });
      }
    });

    document.getElementById('resetSettingsBtn').addEventListener('click', () => {
      if (confirm('Reset all settings to defaults?')) {
        const defaults = {
          enableWarnings: true,
          enableAutoRedact: true,
          enableLogging: true,
          scanDelay: 300
        };

        chrome.storage.local.set({ acgConfig: defaults }, () => {
          this.loadSettings();
          alert('Settings reset to defaults');
        });
      }
    });

    document.getElementById('privacyLink').addEventListener('click', (e) => {
      e.preventDefault();
      // Point to your privacy policy
      window.open('https://example.com/privacy', '_blank');
    });

    document.getElementById('supportLink').addEventListener('click', (e) => {
      e.preventDefault();
      // Point to your support page
      window.open('https://example.com/support', '_blank');
    });
  }

  updateToggleUI(element, enabled) {
    if (enabled) {
      element.classList.add('enabled');
    } else {
      element.classList.remove('enabled');
    }
  }

  saveConfig(updates) {
    chrome.storage.local.get('acgConfig', (result) => {
      const config = result.acgConfig || {
        enableWarnings: true,
        enableAutoRedact: true,
        enableLogging: true,
        scanDelay: 300
      };

      const newConfig = { ...config, ...updates };
      chrome.storage.local.set({ acgConfig: newConfig });

      // Broadcast to all tabs
      chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
          chrome.tabs.sendMessage(tab.id, {
            type: 'CONFIG_UPDATE',
            config: newConfig
          }).catch(() => {});
        });
      });
    });
  }

  renderDetectionTypes() {
    const container = document.getElementById('detectionList');
    container.innerHTML = Object.entries(this.detectionTypes).map(([name, severity]) => {
      const severityClass = `severity-${severity.toLowerCase()}`;
      return `
        <div class="detection-item">
          <div class="detection-item-name">${name}</div>
          <span class="detection-item-severity ${severityClass}">${severity}</span>
        </div>
      `;
    }).join('');
  }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new OptionsManager();
});
