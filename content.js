// Content script for AI Context Guard
// Runs on ChatGPT, Claude, Gemini, Copilot, etc.

class AIContextGuard {
  constructor() {
    this.detector = new (this.initDetector())();
    this.warningShown = false;
    this.currentTextInput = null;
    this.config = {
      enableAutoRedact: true,
      enableWarnings: true,
      enableLogging: true,
      scanDelay: 300
    };

    this.init();
  }

  initDetector() {
    // Inline detector class
    return class DataDetector {
      constructor() {
        this.patterns = {
          aws_key: /(?:A3T[A-Z0-9]|AKIA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
          aws_secret: /aws_secret_access_key\s*=\s*[A-Za-z0-9\/\+]{40}/i,
          api_key: /api[_-]?key\s*[:=]\s*['"]\s*[A-Za-z0-9\-_.]{20,}\s*['"]/gi,
          bearer_token: /bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
          db_connection: /(?:mongodb|mysql|postgresql|oracle)[\w+]*:\/\/[^\s]+/gi,
          connection_string: /(?:password|pwd|passwd)=([^\s;]+)/gi,
          jwt: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
          github_token: /ghp_[A-Za-z0-9_]{36,255}/g,
          github_pat: /github_pat_[A-Za-z0-9_]{22,}_[A-Za-z0-9_]{59,}/g,
          slack_token: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9_-]*/g,
          stripe_key: /sk_(?:live|test)_[0-9a-zA-Z]{24,}/g,
          private_key: /-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----/gi,
          rsa_private_key: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/gi,
          ssn: /\b(?!000|666)[0-6][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b/g,
          credit_card: /\b(?:\d[ -]*?){13,19}\b/g,
          passport: /(?:passport|passport number|passport #)\s*[:=]?\s*[a-z0-9]{6,9}/gi,
          drivers_license: /(?:dl|driver'?s?\s*license|driver'?s?\s*lic)\s*[:=]?\s*[a-z0-9]{5,8}/gi,
          phone_us: /\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b/g,
          email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
          medical_record: /(?:mrn|medical record number)\s*[:=]?\s*[a-z0-9]{5,15}/gi,
          insurance_id: /(?:insurance id|policy number|member id)\s*[:=]?\s*[a-z0-9]{5,20}/gi,
          internal_ip: /(?:192\.168|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)[0-9]{1,3}\.[0-9]{1,3}/g,
          localhost: /localhost(?::\d+)?|127\.0\.0\.1(?::\d+)?/g,
          internal_domain: /https?:\/\/(?:internal|staging|dev|local|vpn|admin|intranet)\.[a-z0-9-]+\.[a-z]{2,}/gi,
          sql_password: /password\s*=\s*['"][^'"]{8,}['"]/gi,
          env_variables: /(?:DATABASE_URL|REDIS_URL|MONGO_URL|API_URL|SECRET_KEY|PRIVATE_KEY)\s*=\s*[^\n]*/gi,
          hardcoded_secret: /(?:secret|password|api_key|token|key)\s*[:=]\s*['"`][^'"`]{8,}['"`]/gi,
          iban: /\b(?:[A-Z]{2}[ \-]?[0-9]{1,5}[ \-]?(?:[A-Z0-9][ \-]?){1,30})\b/gi,
          swift_code: /\b([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b/g,
          aws_url: /https?:\/\/s3[.-](?:ap|eu|us|cn)[.-][a-z0-9-]+\.amazonaws\.com/gi,
          datadog_key: /dd_trace_[a-f0-9]{32}/gi,
          vault_token: /hvs\.[a-zA-Z0-9_-]{90,}/g
        };

        this.severityMap = {
          aws_key: 'CRITICAL', aws_secret: 'CRITICAL', private_key: 'CRITICAL',
          rsa_private_key: 'CRITICAL', jwt: 'HIGH', github_token: 'CRITICAL',
          github_pat: 'CRITICAL', slack_token: 'CRITICAL', stripe_key: 'CRITICAL',
          database_url: 'CRITICAL', db_connection: 'CRITICAL', connection_string: 'HIGH',
          ssn: 'CRITICAL', credit_card: 'CRITICAL', passport: 'HIGH',
          drivers_license: 'HIGH', api_key: 'HIGH', bearer_token: 'HIGH',
          email: 'MEDIUM', phone_us: 'MEDIUM', internal_ip: 'HIGH',
          localhost: 'MEDIUM', internal_domain: 'HIGH', sql_password: 'CRITICAL',
          env_variables: 'HIGH', hardcoded_secret: 'HIGH', iban: 'CRITICAL',
          swift_code: 'HIGH', aws_url: 'HIGH', datadog_key: 'CRITICAL',
          vault_token: 'CRITICAL'
        };
      }

      detect(text) {
        if (!text || typeof text !== 'string') return [];
        const findings = [];
        const seen = new Set();

        for (const [patternName, pattern] of Object.entries(this.patterns)) {
          let match;
          const regex = new RegExp(pattern);

          if (pattern.global) {
            while ((match = pattern.exec(text)) !== null) {
              const value = match[0];
              const key = `${patternName}:${value}`;
              if (!seen.has(key)) {
                seen.add(key);
                findings.push({
                  type: patternName,
                  value: this.redact(value),
                  severity: this.severityMap[patternName] || 'MEDIUM',
                  startIndex: match.index,
                  endIndex: match.index + value.length
                });
              }
            }
          } else {
            match = regex.exec(text);
            if (match) {
              const value = match[0];
              const key = `${patternName}:${value}`;
              if (!seen.has(key)) {
                seen.add(key);
                findings.push({
                  type: patternName,
                  value: this.redact(value),
                  severity: this.severityMap[patternName] || 'MEDIUM',
                  startIndex: match.index,
                  endIndex: match.index + value.length
                });
              }
            }
          }
        }

        return findings.sort((a, b) => b.startIndex - a.startIndex);
      }

      redact(value) {
        if (!value) return '[REDACTED]';
        if (value.length <= 4) return '*'.repeat(value.length);
        return value.substring(0, 2) + '*'.repeat(Math.max(4, value.length - 4)) + value.substring(value.length - 2);
      }

      scrubText(text, findings) {
        if (!findings || findings.length === 0) return text;
        let result = text;
        findings.forEach(finding => {
          const original = finding.value;
          result = result.replace(new RegExp(original.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '[REDACTED]');
        });
        return result;
      }
    };
  }

  init() {
    this.setupTextboxMonitoring();
    this.setupClipboardInterception();
    this.setupConfigSync();
  }

  setupTextboxMonitoring() {
    document.addEventListener('focus', (e) => this.onFocus(e), true);
    document.addEventListener('input', (e) => this.onInput(e), true);
    document.addEventListener('paste', (e) => this.onPaste(e), true);
  }

  onFocus(event) {
    const target = event.target;
    if (this.isRelevantInput(target)) {
      this.currentTextInput = target;
    }
  }

  onInput(event) {
    const target = event.target;
    if (!this.isRelevantInput(target)) return;

    clearTimeout(this.scanTimeout);
    this.scanTimeout = setTimeout(() => {
      this.scanText(target.value, target);
    }, this.config.scanDelay);
  }

  onPaste(event) {
    const target = event.target;
    if (!this.isRelevantInput(target)) return;

    const pasted = (event.clipboardData || window.clipboardData).getData('text');
    const findings = this.detector.detect(pasted);

    if (findings.length > 0) {
      event.preventDefault();
      this.showWarning(findings, pasted, target);
    }
  }

  scanText(text, target) {
    const findings = this.detector.detect(text);
    if (findings.length > 0 && this.config.enableWarnings) {
      this.showWarning(findings, text, target);
    }
  }

  showWarning(findings, text, target) {
    if (this.warningShown) return;
    this.warningShown = true;

    const critical = findings.filter(f => f.severity === 'CRITICAL').length;
    const high = findings.filter(f => f.severity === 'HIGH').length;

    const warningDiv = document.createElement('div');
    warningDiv.id = 'acg-warning-overlay';
    warningDiv.className = `acg-warning acg-severity-${critical > 0 ? 'critical' : 'high'}`;
    warningDiv.innerHTML = `
      <div class="acg-warning-content">
        <div class="acg-warning-header">
          <span class="acg-warning-icon">⚠️</span>
          <span class="acg-warning-title">Data Leak Detected</span>
          <button class="acg-close-btn" onclick="this.parentElement.parentElement.remove()">×</button>
        </div>
        <div class="acg-warning-body">
          <p class="acg-warning-message">
            You're about to leak <strong>${critical} CRITICAL</strong> and <strong>${high} HIGH</strong> severity items.
          </p>
          <div class="acg-findings-preview">
            ${findings.slice(0, 3).map(f => `<span class="acg-finding-type">${f.type}</span>`).join('')}
            ${findings.length > 3 ? `<span class="acg-finding-more">+${findings.length - 3}</span>` : ''}
          </div>
        </div>
        <div class="acg-warning-actions">
          <button class="acg-btn acg-btn-redact" id="acg-redact-btn">Auto-Redact & Paste</button>
          <button class="acg-btn acg-btn-cancel" id="acg-cancel-btn">Cancel</button>
          <button class="acg-btn acg-btn-force" id="acg-force-btn">Continue Anyway</button>
        </div>
      </div>
    `;

    document.body.appendChild(warningDiv);

    document.getElementById('acg-redact-btn').onclick = () => {
      const scrubbed = this.detector.scrubText(text, findings);
      target.value = scrubbed;
      target.dispatchEvent(new Event('input', { bubbles: true }));
      this.logEvent('redacted', findings);
      warningDiv.remove();
      this.warningShown = false;
    };

    document.getElementById('acg-cancel-btn').onclick = () => {
      target.value = '';
      target.focus();
      this.logEvent('cancelled', findings);
      warningDiv.remove();
      this.warningShown = false;
    };

    document.getElementById('acg-force-btn').onclick = () => {
      this.logEvent('forced', findings);
      warningDiv.remove();
      this.warningShown = false;
    };

    document.querySelector('.acg-close-btn').onclick = () => {
      this.warningShown = false;
    };
  }

  isRelevantInput(element) {
    if (!element) return false;
    const tagName = element.tagName.toLowerCase();
    const isTextarea = tagName === 'textarea';
    const isContentEditable = element.contentEditable === 'true';
    const isAIWebsite = /chatgpt|claude|gemini|copilot|bard/.test(window.location.hostname);

    return isAIWebsite && (isTextarea || isContentEditable || this.isInputLike(element));
  }

  isInputLike(element) {
    if (element.tagName.toLowerCase() !== 'input') return false;
    const type = element.type.toLowerCase();
    return ['text', 'search', 'email', 'url', 'tel'].includes(type);
  }

  setupClipboardInterception() {
    // Optional: intercept clipboard operations
    document.addEventListener('copy', (e) => {
      if (this.currentTextInput) {
        const text = this.currentTextInput.value || this.currentTextInput.textContent;
        const findings = this.detector.detect(text);
        if (findings.length > 0) {
          this.logEvent('clipboard_copy_detected', findings);
        }
      }
    });
  }

  setupConfigSync() {
    chrome.storage.local.get('acgConfig', (result) => {
      if (result.acgConfig) {
        this.config = { ...this.config, ...result.acgConfig };
      }
    });

    chrome.storage.onChanged.addListener((changes) => {
      if (changes.acgConfig) {
        this.config = { ...this.config, ...changes.acgConfig.newValue };
      }
    });
  }

  logEvent(action, findings) {
    const event = {
      timestamp: new Date().toISOString(),
      action,
      url: window.location.href,
      findingsCount: findings.length,
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      types: [...new Set(findings.map(f => f.type))]
    };

    chrome.storage.local.get('acgEvents', (result) => {
      const events = result.acgEvents || [];
      events.push(event);
      events.splice(0, Math.max(0, events.length - 1000)); // Keep last 1000
      chrome.storage.local.set({ acgEvents: events });
    });
  }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    new AIContextGuard();
  });
} else {
  new AIContextGuard();
}
