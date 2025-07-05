# 🕵️‍♀️ THREAT HUNT REPORT: UNAUTHORIZED TOR USAGE

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

---

## 👩‍💻 ENVIRONMENT & TOOLS UTILIZED

- **Virtual Machines:**  
  Windows 10 VMs hosted on Microsoft Azure

- **Endpoint Detection & Response (EDR):**  
  Microsoft Defender for Endpoint

- **Query Language:**  
  Kusto Query Language (KQL) – Used for querying telemetry data in Defender and Azure environments

- **Privacy Browser:**  
  Tor Browser – Used for anonymized browsing and testing network detection rules


---

### [SCENARIO CREATION](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

##  SCENARIO OVERVIEW

Management has raised concerns about potential TOR browser usage within the organization after recent network logs revealed unusual encrypted traffic patterns and connections to known TOR entry nodes. Compounding these concerns, anonymous reports have surfaced indicating that employees may be discussing ways to access restricted websites during work hours.

## OBJECTIVE

Detect any unauthorized installation or use of the TOR browser on corporate workstations. Identify related security incidents, assess the scope of activity, and evaluate potential risks to the organization’s network and data security. If any TOR usage is detected, promptly report findings to management for further action.

## HIGH-LEVEL TOR-RELATED IOC DISCOVERY PLAN

### File Activity Analysis — `DeviceFileEvents`

- Search for file events involving tor.exe, firefox.exe, or other executables commonly associated with the TOR browser.
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

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
