// Detection patterns for secrets, PII, PHI, and sensitive data
class DataDetector {
  constructor() {
    this.patterns = {
      // AWS
      aws_key: /(?:A3T[A-Z0-9]|AKIA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
      aws_secret: /aws_secret_access_key\s*=\s*[A-Za-z0-9\/\+]{40}/i,
      
      // API Keys
      api_key: /api[_-]?key\s*[:=]\s*['"]\s*[A-Za-z0-9\-_.]{20,}\s*['"]/gi,
      bearer_token: /bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
      
      // Database
      db_connection: /(?:mongodb|mysql|postgresql|oracle)[\w+]*:\/\/[^\s]+/gi,
      connection_string: /(?:password|pwd|passwd)=([^\s;]+)/gi,
      
      // Tokens & Credentials
      jwt: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
      github_token: /ghp_[A-Za-z0-9_]{36,255}/g,
      github_pat: /github_pat_[A-Za-z0-9_]{22,}_[A-Za-z0-9_]{59,}/g,
      slack_token: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9_-]*/g,
      stripe_key: /sk_(?:live|test)_[0-9a-zA-Z]{24,}/g,
      
      // SSH & Private Keys
      private_key: /-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----/gi,
      rsa_private_key: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/gi,
      
      // PII (Personally Identifiable Information)
      ssn: /\b(?!000|666)[0-6][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b/g,
      credit_card: /\b(?:\d[ -]*?){13,19}\b/g,
      passport: /(?:passport|passport number|passport #)\s*[:=]?\s*[a-z0-9]{6,9}/gi,
      drivers_license: /(?:dl|driver'?s?\s*license|driver'?s?\s*lic)\s*[:=]?\s*[a-z0-9]{5,8}/gi,
      
      // Phone Numbers
      phone_us: /\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b/g,
      
      // Email
      email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      
      // PHI (Protected Health Information)
      medical_record: /(?:mrn|medical record number)\s*[:=]?\s*[a-z0-9]{5,15}/gi,
      insurance_id: /(?:insurance id|policy number|member id)\s*[:=]?\s*[a-z0-9]{5,20}/gi,
      
      // Internal URLs & IPs
      internal_ip: /(?:192\.168|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)[0-9]{1,3}\.[0-9]{1,3}/g,
      localhost: /localhost(?::\d+)?|127\.0\.0\.1(?::\d+)?/g,
      internal_domain: /https?:\/\/(?:internal|staging|dev|local|vpn|admin|intranet)\.[a-z0-9-]+\.[a-z]{2,}/gi,
      
      // Source Code Patterns
      sql_password: /password\s*=\s*['"][^'"]{8,}['"]/gi,
      env_variables: /(?:DATABASE_URL|REDIS_URL|MONGO_URL|API_URL|SECRET_KEY|PRIVATE_KEY)\s*=\s*[^\n]*/gi,
      hardcoded_secret: /(?:secret|password|api_key|token|key)\s*[:=]\s*['"`][^'"`]{8,}['"`]/gi,
      
      // Financial Info
      iban: /\b(?:[A-Z]{2}[ \-]?[0-9]{1,5}[ \-]?(?:[0-9A-Z][ \-]?){1,30})\b/gi,
      swift_code: /\b([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b/g,
      
      // Additional High-Risk Patterns
      aws_url: /https?:\/\/s3[.-](?:ap|eu|us|cn)[.-][a-z0-9-]+\.amazonaws\.com/gi,
      datadog_key: /dd_trace_[a-f0-9]{32}/gi,
      vault_token: /hvs\.[a-zA-Z0-9_-]{90,}/g
    };

    this.severityMap = {
      aws_key: 'CRITICAL',
      aws_secret: 'CRITICAL',
      private_key: 'CRITICAL',
      rsa_private_key: 'CRITICAL',
      jwt: 'HIGH',
      github_token: 'CRITICAL',
      github_pat: 'CRITICAL',
      slack_token: 'CRITICAL',
      stripe_key: 'CRITICAL',
      database_url: 'CRITICAL',
      db_connection: 'CRITICAL',
      connection_string: 'HIGH',
      ssn: 'CRITICAL',
      credit_card: 'CRITICAL',
      passport: 'HIGH',
      drivers_license: 'HIGH',
      api_key: 'HIGH',
      bearer_token: 'HIGH',
      email: 'MEDIUM',
      phone_us: 'MEDIUM',
      internal_ip: 'HIGH',
      localhost: 'MEDIUM',
      internal_domain: 'HIGH',
      sql_password: 'CRITICAL',
      env_variables: 'HIGH',
      hardcoded_secret: 'HIGH',
      iban: 'CRITICAL',
      swift_code: 'HIGH',
      aws_url: 'HIGH',
      datadog_key: 'CRITICAL',
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

      // Handle non-global patterns
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
              endIndex: match.index + value.length,
              rawLength: value.length
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
              endIndex: match.index + value.length,
              rawLength: value.length
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
      const regex = new RegExp(finding.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
      result = result.replace(regex, '[REDACTED]');
    });

    return result;
  }

  getSeverityScore(findings) {
    const scores = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 };
    if (findings.length === 0) return 0;
    return Math.max(...findings.map(f => scores[f.severity] || 0));
  }

  formatReport(findings) {
    if (findings.length === 0) return null;

    const grouped = {};
    findings.forEach(finding => {
      if (!grouped[finding.type]) grouped[finding.type] = [];
      grouped[finding.type].push(finding);
    });

    return {
      totalFindings: findings.length,
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      byType: grouped,
      maxSeverity: findings.reduce((max, f) => {
        const scores = { CRITICAL: 3, HIGH: 2, MEDIUM: 1 };
        return Math.max(max, scores[f.severity] || 0);
      }, 0)
    };
  }
}

// Export for use in content scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = DataDetector;
}
