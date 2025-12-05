# 🛡️ AI Context Guard

**Enterprise AI Security & Data Protection Extension**

AI Context Guard is a professional Chrome extension designed to prevent accidental data leaks when using AI platforms like ChatGPT, Claude, Gemini, and Microsoft Copilot. It provides real-time detection of secrets, PII, credentials, and sensitive data with intelligent auto-redaction capabilities.

## ✨ Key Features

### 🔍 Advanced Detection Engine
- **Critical Threats**: AWS keys, API tokens, private keys, database credentials
- **PII Protection**: SSN, credit cards, phone numbers, email addresses  
- **Code Security**: Environment variables, connection strings, hardcoded secrets
- **Financial Data**: IBAN, SWIFT codes, insurance IDs

### 🛡️ Real-Time Protection
- Live scanning as you type with configurable delay
- Instant clipboard monitoring for paste operations
- Smart context-aware detection algorithms
- Zero false positives on common text patterns

### 🎯 Enterprise Features
- **Auto-Redaction**: One-click data sanitization
- **Audit Logging**: Complete event history for compliance
- **Configurable Policies**: Customize detection sensitivity
- **Professional UI**: Clean, enterprise-grade interface

## 🚀 Installation

### For Chrome Web Store Deployment:
1. Download the extension package
2. Extract to desired directory
3. Generate new icons using `generate-icons.html`
4. Replace icons in `/images/` directory
5. Test thoroughly in developer mode
6. Submit to Chrome Web Store

### For Developer Testing:
1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" in the top right
3. Click "Load unpacked" and select the extension directory
4. The AI Context Guard icon should appear in your extensions

## 🔧 Configuration

### Settings Panel
Access via extension popup → "Full Settings" button:

- **Enable Warnings**: Show alerts when sensitive data detected
- **Auto-Redaction**: Automatically sanitize detected content
- **Event Logging**: Maintain audit trail for compliance
- **Scan Delay**: Adjust real-time scanning sensitivity (100-1000ms)

### Popup Features
- **Size Cycling**: Double-click header or press Ctrl/Cmd+R
- **Live Statistics**: Today's activity and detection counts
- **Quick Toggles**: Rapidly enable/disable protection features
- **Event History**: Recent detection events with timestamps

## 🌐 Supported Platforms

### AI Platforms Monitored:
- **OpenAI ChatGPT** (chatgpt.com, chat.openai.com)
- **Anthropic Claude** (claude.ai)
- **Google Gemini** (gemini.google.com)
- **Microsoft Copilot** (copilot.microsoft.com)
- **Google Bard** (bard.google.com)

## 🔒 Privacy & Security

### Local Processing Only
- All detection occurs entirely within your browser
- No data transmitted to external servers
- Zero network requests for content analysis
- Complete user privacy protection

### Data Handling
- Events stored locally using Chrome's secure storage API
- Automatic cleanup of old events (7-day retention)
- No PII stored in logs (only detection metadata)
- GDPR and enterprise compliance ready

## 📞 Support & Contact

### Technical Support:
- **Email**: borgaonkar.swaranshu@gmail.com
- **Subject**: AI Context Guard Support Request
- **Response Time**: 48 hours maximum

---

**AI Context Guard v1.0.0**  
© 2025 | Enterprise AI Security & Data Protection  
Built with privacy-first principles and enterprise-grade security

*Protecting your sensitive data, one AI conversation at a time.* 🛡️
