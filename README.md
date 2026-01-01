# 🛡️ Aegis Ultra v1.0
### **Advanced Windows Audit, Hygiene & Security Engine**
**Author:** Bilel Jelassi | **Engine:** PowerShell Core | **Version:** 1.0 (Official Release)

---

## 🔍 Overview
Aegis Ultra is a high-performance, single-file PowerShell engine designed to provide deep visibility into Windows systems. It focuses on security posture, system hygiene, and operational transparency. 

Unlike "cleaners" or "boosters," Aegis Ultra follows a Safe-by-Default philosophy—it performs deep audits using native Windows components without modifying registry settings or deleting user data.

## ✨ Core Features
* System Topology Audit: Real-time hardware identity and memory load analysis.
* Network Perimeter Analysis: External IP detection and firewall status verification.
* Defense Posture Check: Real-time monitoring of Windows Defender and BitLocker protection.
* Integrity Verification: Automated SFC (System File Checker) background scans with a functional progress bar.
* Sophisticated UI: "Elite" hacker-style console with animated progress bars and spinners.
* Enterprise Logging: Continuous auditing with logs stored in C:\ProgramData\AegisUltra.

---

## 🚀 Installation & Usage

### 1. Automatic Setup (Recommended)
To download and prepare the engine, open PowerShell (as Administrator) and run:

# Clone the repository
git clone https://github.com/Billybu092/Aegis-Ultra-v1.0.git

# Enter the directory
cd Aegis-Ultra-v1.0

# Run the official installer (Sets up folders and automation)
.\Install-AegisUltra v1.0 .ps1

### 2. Manual Execution
If you wish to run a one-time audit without installing:

powershell -ExecutionPolicy Bypass -File .\Aegis-Ultra v1.0 .ps1

---

## ⚙️ Design Principles
* Single File Architecture: Zero external dependencies; easy to deploy.
* Non-Destructive: Performs read-only audits to ensure system stability.
* Transparency: Built for power users and cybersecurity enthusiasts who need to see exactly what is happening under the hood.

## 🔐 Automation
Aegis Ultra is automation-ready. By running the Install-AegisUltra.ps1 script, a Windows Scheduled Task is created to perform daily audits, ensuring your system integrity logs are always up to date.

---

## 📊 Technical Requirements
* OS: Windows 10 / 11
* Shell: PowerShell 5.1+ (Run as Administrator)
* Encoding: UTF-8 with BOM (Recommended for UI symbols)

---

## ⚠️ Disclaimer
This tool is provided "as is". While it performs read-only audits by default, always review the code before execution in production environments.

---

## 👤 Author
Bilel Jelassi
IT Enthusiast & Security Developer
GitHub: https://github.com/Billybu092
