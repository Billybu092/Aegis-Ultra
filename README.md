# 🛡️ Aegis Ultra v1.0 (Sovereign Forensic Edition)
### **Elite Windows Threat Hunting, Forensic Audit & System Hardening Engine**
**Author:** Bilel Jelassi | **Engine:** PowerShell Core | **Version:** 3.0 (Ultimate)

---

## 🔍 Overview
Aegis Ultra is a high-performance forensic engine designed to move beyond simple system cleaning. It focuses on **Active Threat Hunting**, **Kernel-Level Integrity**, and **Forensic Visibility**. By auditing the "unseen" areas of Windows, it detects backdoors, persistence mechanisms, and hardware degradation that standard tools miss.

## ✨ Why Aegis Ultra isn't "Basic"
This engine performs deep-level forensic analysis typically reserved for Incident Response teams:

* **Registry Stalking:** Automatically crawls `HKLM` and `HKCU` hives to expose programs hiding in auto-start entries where spyware typically resides.
* **Shadow Admin Audit:** Scans the local Administrators group to find "God Mode" accounts that shouldn't be there, identifying potential privilege escalation.
* **Malware Hunting (VirusTotal Integration):** Audits `System32` DLL digital signatures. If an unsigned or modified DLL is found, the engine queries the **VirusTotal API** to cross-reference the file hash with global threat intelligence.
* **Port Listener Intelligence:** Maps active listeners to specific processes. It whitelists standard Windows services and flags unknown ports that often signify a backdoor or RAT (Remote Access Tool).
* **Anti-Spoofing Engine:** Detects critical system processes (like `svchost.exe` or `lsass.exe`) running from unauthorized directories instead of `System32`.
* **WMI Persistence Hunting:** Scans for hidden scripts in WMI Event Consumers—a common technique used by advanced persistent threats (APTs) to stay hidden.
* **NVMe Health Analysis:** Performs S.M.A.R.T. health checks specifically optimized for high-performance SSDs to predict drive failure.
* **Service Path Auditing:** Scans Windows services for suspicious executable paths outside of standard system directories.

---

## 🚀 Setup & VirusTotal Integration

### 1. Installation
Run the following in an **Administrator PowerShell**:
```powershell
# Clone the repository
git clone https://github.com/Billybu092/Aegis-Ultra.git

# Enter the directory
cd Aegis-Ultra

# Run the installer
.\Install-AegisUltra.ps1
```
----

### 2. ⚡ Enabling Cloud Intelligence (Optional)
To enable VirusTotal malware verification, you must set your API key as an environment variable. This professional practice keeps your key private and out of the source code:

🔑 Get a free key from VirusTotal.com.

💻 Run this command in PowerShell:

[Environment]::SetEnvironmentVariable("VT_API_KEY", "YOUR_API_KEY_HERE", "User")

🔄 Restart your terminal and run Aegis Ultra. It will now automatically perform cloud-verified audits.


📊 Forensic Reporting
Every scan generates a timestamped, color-coded report secured in:

Documents\SystemLogs\Aegis_Forensic_Report_YYYYMMDD.log

---

### 👤 Author

⭐ Bilel Jelassi 🛠️ IT Enthusiast 

🔗 GitHub Profile: https://github.com/Billybu092

---

### ⚠️ Disclaimer

Aegis Ultra is a forensic audit tool. Always review the code before execution in enterprise production environments.
