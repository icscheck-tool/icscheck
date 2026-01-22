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

```powershell
# Run as Administrator on your ICS workstation
git clone https://github.com/icscheck-tool/icscheck.git
cd icscheck/src
.\ICScheck.ps1
The tool will:

Scan your system configuration
Check against 25+ security controls
Generate an HTML compliance report
Provide remediation recommendations
📊 What Does It Check?
Category	Checks	IEC 62443
Access Control	Users, passwords, lockout policies	FR1
Use Control	USB, autorun, admin rights	FR2
System Integrity	Antivirus, updates, patches	FR3
Data Confidentiality	Shares, encryption	FR4
Network Security	Firewall, open ports, RDP	FR5
Audit & Logging	Event logs, retention	FR6
Availability	Backups, restore points	FR7
📈 Sample Report
After running ICScheck, you'll receive:

Compliance Score - X% aligned with IEC 62443 / NIS2
Pass/Fail Status - For each security control
Risk Assessment - Prioritized findings
Remediation Steps - How to fix each issue
Export Options - HTML report for auditors
🗺️ Roadmap
Completed:

✅ Core PowerShell audit engine
✅ IEC 62443-3-3 mapping
✅ NIS2 Article 21 mapping
✅ HTML report generation
Coming Soon:

🔜 PDF export
🔜 NIST CSF mapping
🔜 Scheduled scans
🔜 Central dashboard (Pro)
🔜 Multi-language support
🤝 Contributing
Contributions are welcome!

Ways to contribute:

🐛 Report bugs
💡 Suggest new checks
📖 Improve documentation
🔧 Submit pull requests
📄 License
MIT License - Use it, modify it, share it. No restrictions.

👨‍💻 Author
Łukasz Krzesiński

17 years in industrial automation
140+ SCADA/HMI/DCS systems delivered
Certified Siemens SIMATIC specialist
📧 hello@icscheck.com

🌐 icscheck.com

⭐ Support the Project
If ICScheck helps you, please:

⭐ Star this repository
🐛 Report issues
📢 Share with colleagues
Secure your ICS. Achieve compliance. Sleep better.

Made with ❤️ for the industrial automation community
