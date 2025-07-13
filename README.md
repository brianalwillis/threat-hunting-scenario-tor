<h1 = align=center>THREAT HUNT REPORT</h1>
<h2 = align=center>Unauthorized Tor Browser Usage</h2>

<p align="center">
<img width="500" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/></br>
</p>

## 🧅 "What is Tor?"

Tor stands for `The Onion Router`. The Tor Browser is a privacy-focused web browser that allows users to access the internet anonymously by routing traffic through a network of volunteer-operated servers. Using the Tor Browser at work can signal a serious breach of trust and policy, even if the intent isn't malicious. It compromises visibility, security, and accountability—three pillars of enterprise IT management.

---

## 🛠️ Technology & Tools Utilized

- `Microsoft Azure:`</br>
Windows 10 virtual machines were hosted on Azure for the simulation environment.

- `Microsoft Defender for Endpoint:`</br>
Used as the primary Endpoint Detection & Response (EDR) solution to monitor and protect system activity.

- `Kusto Query Language (KQL):`</br>
Used to query telemetry data from Microsoft Defender and Azure services.

- `Tor Browser:`</br>
Utilized for anonymized browsing and to test detection rules related to privacy-focused network traffic.

---

## [SCENARIO CREATION](https://github.com/brianalwillis/threat-hunting-scenario-tor/blob/main/scenario-creation)

##  Scenario Overview

Management has raised concerns about potential TOR browser usage within the organization after recent network logs revealed unusual encrypted traffic patterns and connections to known TOR entry nodes. Compounding these concerns, anonymous reports have surfaced indicating that employees may be discussing ways to access restricted websites during work hours.

## Objective

Detect any unauthorized installation or use of the TOR browser on corporate workstations. Identify related security incidents, assess the scope of activity, and evaluate potential risks to the organization’s network and data security. If any TOR usage is detected, promptly report findings to management for further action.

## HIGH-LEVEL TOR-RELATED IOC DISCOVERY PLAN

### File Activity Analysis — `DeviceFileEvents`

- Search for file events involving `tor.exe`, `firefox.exe`, or other executables commonly associated with the TOR browser.
- Focus on unusual file creation, modification, or execution patterns that may indicate installation or launch activity.

### Process Activity Monitoring — `DeviceProcessEvents`

- Identify processes related to TOR browser installation or execution.
- Look for command-line arguments, parent-child process relationships, and unusual process trees involving TOR-related binaries.

### Network Traffic Analysis — `DeviceNetworkEvents`

- Detect outbound connections to known TOR entry or relay nodes.
- Monitor traffic over common TOR ports (e.g., 9001, 9030, 9050, 9051, 9150).
- Analyze encrypted traffic anomalies that may indicate TOR usage.

---

## STEPS TAKEN

### Step 1: Initial File Detection

I queried the `DeviceFileEvents` table to look for any file activity that might be related to the TOR browser. Specifically, I'm filtering for file names that contain the string `tor`—this could include files like `tor.exe`, `tor-browser.exe`, or any related components. This is where I discovered that the user `bwillis` had downloaded a TOR installer.

**Query:**
```kql
DeviceFileEvents
| where FileName  contains "tor"
| order by Timestamp desc
```

**Results:**

![TOR 1](https://github.com/user-attachments/assets/6d5173bf-b273-411e-814a-db5ad65f2366)

---

### Step 2: Scoped Investigation by User and Host

After identifying suspicious activity linked to a specific user, I narrowed my investigation to focus on that individual. In this case, I'm querying the `DeviceFileEvents` table to look for TOR-related file activity associated with the user `bwillis` on the device `willis-threat-h`.

**Query:**
```kql
DeviceFileEvents
| where DeviceName == "willis-threat-h"
| where InitiatingProcessAccountName == "bwillis"
| where FileName  contains "tor"
| order by Timestamp desc
```

**Results:**

![TOR 2](https://github.com/user-attachments/assets/3bb21c90-c2a5-4d02-b1f2-159ed3e045f6)

---

### Step 3: Timeline Refinement

At this stage, I'm refining my query to isolate and display only the most relevant details about the suspicious TOR-related activity. I'm focusing on events that occurred after the specific timestamp when the suspicious activity began: `2025-07-05T00:58:17.8896593Z`.

**Query:**
```kql
DeviceFileEvents
| where DeviceName == "willis-threat-h"
| where InitiatingProcessAccountName == "bwillis"
| where FileName  contains "tor"
| where Timestamp >= datetime(2025-07-05T00:58:17.8896593Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName
```

**Results:**

![TOR 3](https://github.com/user-attachments/assets/3be9cbae-e31e-4c1e-b2dd-9af58961f294)

---

### Step 4: TOR Installer Execution Confirmations

To further investigate the suspicious TOR-related activity by the user `bwillis`, I ran a query against the `DeviceProcessEvents` table. I filtered the results to focus on the device `willis-threat-h` and looked specifically for any process execution involving the file `tor-browser-windows-x86_64-portable-14.5.4.exe` — a known TOR browser installer.

**Query:**
```kql
DeviceProcessEvents
| where DeviceName == "willis-threat-h"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
```

**Results:**

![TOR 4](https://github.com/user-attachments/assets/6be620e5-16ea-409d-a6f0-6dc3a0747a2d)

This result shows that the user `bwillis` executed the TOR browser installer on `July 4, 2025`, using the silent install flag `/S`, which allows the installation to proceed without any user interface or prompts. This indicates a deliberate attempt to install TOR quietly, potentially to avoid detection. This is a strong indicator of intentional and unauthorized TOR browser deployment on a corporate device.

---

### Step 5: File Creation of TOR Components

To confirm whether the user `bwillis` launched or initialized the TOR browser after downloading the installer, I ran a focused query on the `DeviceFileEvents` table. My goal was to detect the creation or execution of any key TOR-related executable files (`tor.exe`, `firefox.exe`, `tor-browser.exe`)_ on the device `willis-threat-h`.

**Query:**
```kql
DeviceFileEvents
| where DeviceName == "willis-threat-h"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, FileName, SHA256, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Results:**

![TOR 5](https://github.com/user-attachments/assets/1528ea8e-004c-45b8-99af-19083c561c01)

Both `tor.exe` and `firefox.exe` were created on the system shortly after the TOR installer (`tor-browser-windows-x86_64-portable-14.5.4.exe`) was executed using the `/S` flag.

The file creation activity indicates that the TOR browser was not just downloaded—it was successfully installed, and the core components (including the TOR relay and Firefox-based browser) were deployed to the system.

---

### Step 6: TOR Browser Network Activity

To determine whether the user `bwillis` used the TOR browser to access the internet, I queried the `DeviceNetworkEvents` table. I focused on traffic on known TOR-related ports: `9001`, `9030`, `9040`, `9050`, `9051`, and `9150`.

**Query:**
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where DeviceName == "willis-threat-h"
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

**Results:**

![TOR 6](https://github.com/user-attachments/assets/a527ed7a-bb6d-45a9-9df5-89de9e5e82e7)

The results show that on `July 4, 2025` the user `bwillis`’ device `willis-threat-h` initiated multiple network connections via `tor.exe` to several external IP addresses on known TOR relay ports such as `9001` and `9030`. Additionally, `firefox.exe` connected locally to `127.0.0.1` on port `9150`, which is the standard SOCKS proxy port used by TOR. These connections indicate that the TOR browser was actively running and routing traffic through the TOR network, confirming the user’s actual use of TOR for internet browsing.

---

### Step 7: Suspicious File Created and Deleted

I discovered that the user `bwillis` created and later deleted a file named `tor-shopping-list.txt` on the device `willis-threat-h`. Using a query focused on file events involving "`tor-shopping-list.txt`", I found that the file was created at `2025-07-05T01:16:30.4626442Z` by `notepad.exe`, located on the user’s desktop. This indicates that the user manually created this note, possibly related to their TOR usage. The file size was `39 bytes`, and the file was later deleted, suggesting an attempt to remove evidence of TOR-related activity.

**Query:**
```kql
DeviceFileEvents
| where FileName contains "shopping-list.txt"
| where DeviceName == "willis-threat-h"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, InitiatingProcessFileName, FolderPath, SHA256, FileSize
```

**Results:**

![TOR 7](https://github.com/user-attachments/assets/c9ddc3bf-e5b4-43c7-9b6e-411a9d8823af)

---

## CHRONOLOGICAL EVENT TIMELINE

### Step 1: Initial File Detection  
**Timestamp:** `2025-07-05T01:16:30.4626442Z`  
**Event:** TOR-related File Detection  
**Action:** Detected TOR-related file activity using `DeviceFileEvents`  
**File Path:** N/A (Initial scope-wide search)

### Step 2: Scoped Investigation by User and Host  
**Timestamp:** `2025-07-05T00:58:17.8896593Z`  
**Event:** Filtered for Specific Devices and User  
**Action:** Focused on user `bwillis` and device `willis-threat-h`  
**File Path:** Files matching "tor" under this user's activity

### Step 3: Timeline Refinement  
**Timestamp:** `2025-07-05T00:58:17.8896593Z`  
**Event:** Time-based Filtering  
**Action:** Isolated TOR-related events occurring after suspicious activity started  
**File Path:** `C:\Users\bwillis\Downloads\`

### Step 4: TOR Installer Execution Confirmation  
**Timestamp:** `2025-07-05T01:00:09.6781464Z`  
**Event:** Silent Installation of TOR  
**Action:** Queried `DeviceProcessEvents` for TOR installer execution  
**File Path:** `C:\Users\bwillis\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`

### Step 5: File Creation of TOR Components  
**Timestamp:** `2025-07-05T01:00:10.5918545Z`  
**Event:** TOR Executables Created  
**Action:** Detected creation of `tor.exe` and `firefox.exe`  
**File Path:** Likely under `C:\Users\bwillis\Tor Browser\` or similar

### Step 6: TOR Browser Network Activity  
**Timestamp:** `2025-07-05T01:00:58.8815182Z`  
**Event:** Outbound TOR Network Traffic  
**Action:** Queried `DeviceNetworkEvents` to detect TOR usage  
**File Path:** Process: `tor.exe` and `firefox.exe` → `127.0.0.1:9150`

### Step 7: Suspicious File Created and Deleted  
**Timestamp:** `2025-07-05T01:16:30.4626442Z`  
**Event:** Creation of `tor-shopping-list.txt`  
**Action:** Detected manual creation and later deletion of a TOR-related note  
**File Path:** `C:\Users\bwillis\Desktop\tor-shopping-list.txt`

---

## SUMMARY

The investigation into suspicious activity on the device `willis-threat-h` revealed that the user `bwillis` silently installed the TOR browser using a portable installer with a silent execution flag, indicating intent to bypass detection. Subsequent file and process activity confirmed the creation of key TOR components, including `tor.exe` and `firefox.exe`, followed by network connections to known TOR relay nodes over ports `9001` and `9030`. Notably, `firefox.exe` was observed communicating with `127.0.0.1:9150`, confirming active TOR browser usage. The user also created and later deleted a file named `tor-shopping-list.txt`, suggesting an attempt to hide related activity. This timeline of events confirms unauthorized TOR use, likely to circumvent security controls and access restricted content, warranting escalation and further action.

---

## RESPONSE TAKEN

In response, the device was immediately isolated from the network to prevent further unauthorized activity or data exfiltration. A full forensic capture was initiated, and all findings were documented. During the investigation, we were able to recover the contents of a deleted Notepad file, which contained several illicit items. The user’s direct manager was notified of the incident, and the case was escalated to HR and Information Security for further review and disciplinary consideration.

---

*This project documents a simulated detection and investigation of TOR browser activity using Microsoft Defender for Endpoint telemetry. It showcases how to trace file, process, and network events related to the installation and use of TOR within an enterprise environment.*

**Created By:** `Briana Willis`  
**Date:** `2025-07-05`  
**Time:** `14:32 UTC`

