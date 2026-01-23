# 🛡️ ICScheck

> Free, open-source security audit tool for industrial control systems.
> IEC 62443 & NIS2 compliance assessment in under 30 minutes.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![IEC 62443](https://img.shields.io/badge/IEC_62443-Compliant-orange.svg)](https://www.iec.ch/)
[![NIS2](https://img.shields.io/badge/NIS2-Ready-blue.svg)](https://digital-strategy.ec.europa.eu/en/policies/nis2-directive)

---

## 🎯 What is ICScheck?

A lightweight PowerShell tool that automatically audits your SCADA/HMI/DCS workstation against **IEC 62443** and **NIS2** security requirements.

**No cybersecurity expertise required.** Run the script, get a compliance report.

### ✅ Supported Systems

| System Type | Examples |
|-------------|----------|
| **SCADA** | Siemens WinCC V7/V8, TIA Professional, WinCC Unified, AVEVA InTouch, Rockwell FactoryTalk View SE |
| **HMI** | Siemens Comfort Panels, Rockwell PanelView |
| **DCS** | Siemens PCS7 |
| **BMS** | Building automation systems |
| **PLC/PAC** | Any Windows-based engineering station |

### 📋 Compliance Frameworks

| Framework | Region | Status |
|-----------|--------|--------|
| **IEC 62443-3-3** | 🌍 Global | ✅ Supported |
| **NIS2 Directive** | 🇪🇺 EU | ✅ Supported |
| **NIST CSF** | 🇺🇸 USA | 🔜 Coming soon |

---

## 🚀 Quick Start

Run as **Administrator** on your ICS workstation:

```powershell
git clone https://github.com/icscheck-tool/icscheck.git
cd icscheck/src
powershell -ExecutionPolicy Bypass -File "ICScheck.ps1"
```

> **Note:** The `-ExecutionPolicy Bypass` flag is required because most ICS systems have restricted PowerShell execution policies. This only affects the current script execution and does not change system settings.

**Alternative (if git is not available):**
1. Download ZIP from [GitHub](https://github.com/icscheck-tool/icscheck/archive/refs/heads/main.zip)
2. Extract to any folder
3. Right-click `ICScheck.ps1` → "Run with PowerShell" (as Administrator)

The tool will:
1. Scan your system configuration
2. Check against **36+ security controls**
3. Generate an HTML compliance report
4. Provide remediation recommendations

---

## 📊 What Does It Check?

| Category | Checks | IEC 62443 | NIS2 |
|----------|--------|-----------|------|
| **Access Control** | Users, passwords, lockout, UAC, password age/history | FR1 | Art.21(i) |
| **Use Control** | USB, autorun, screen lock | FR2 | Art.21(g) |
| **System Integrity** | Antivirus, Defender real-time, updates, Secure Boot | FR3 | Art.21(e) |
| **Data Confidentiality** | BitLocker, shares, telemetry | FR4 | Art.21(h) |
| **Network Security** | Firewall, RDP, SMBv1, TLS 1.2+, DCOM hardening | FR5 | Art.21(e) |
| **Audit & Logging** | Event logs, audit policy | FR6 | Art.21(b) |
| **Availability** | System Restore, Shadow Copy | FR7 | Art.21(c) |
| **WinCC Specific** | Users hierarchy, drivers, alarm logging, SQL security | - | Art.21(b) |

---

## 📈 Sample Report

After running ICScheck, you will receive:

- **Compliance Score** - X% aligned with IEC 62443 / NIS2
- **Pass/Fail Status** - For each security control
- **Risk Assessment** - Prioritized findings
- **Remediation Steps** - How to fix each issue
- **Export Options** - HTML report for auditors

---

## 🗺️ Roadmap

**Completed:**
- ✅ Core PowerShell audit engine
- ✅ IEC 62443-3-3 mapping (FR1-FR7)
- ✅ NIS2 Article 21 mapping (~80% coverage)
- ✅ HTML report generation (dark/light theme)
- ✅ WinCC V7/V8 deep integration
- ✅ Communication Architecture tree
- ✅ User hierarchy visualization

**Coming Soon:**
- 🔜 PDF export
- 🔜 NIST CSF mapping
- 🔜 Scheduled scans
- 🔜 Central dashboard (Pro)
- 🔜 Multi-language support

---

## 🤝 Contributing

Contributions are welcome!

**Ways to contribute:**
- 🐛 Report bugs
- 💡 Suggest new checks
- 📖 Improve documentation
- 🔧 Submit pull requests

---

## 📄 License

**MIT License** - Use it, modify it, share it. No restrictions.

---

## 👨‍💻 Author

**Łukasz Krzesiński**

- 17 years in industrial automation
- 140+ SCADA/HMI/DCS systems delivered
- Certified Siemens SIMATIC specialist

📧 hello@icscheck.com

🌐 [icscheck.com](https://icscheck.com)

💼 [LinkedIn](https://www.linkedin.com/in/lukaszkrzesinski/)

---

## ⭐ Support the Project

If ICScheck helps you, please:

- ⭐ **Star** this repository
- 🐛 **Report** issues
- 📢 **Share** with colleagues

---

**Secure your ICS. Achieve compliance. Sleep better.**

Made with ❤️ for the industrial automation community
