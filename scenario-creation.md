# SCENARIO: UNAUTHORIZED TOR USAGE

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

---

## STEPS THE "BAD ACTOR" TOOK TO CREATE LOGS AND IOCs

### Step 1: **Download the TOR Browser Installer** 
[`https://www.torproject.org/download/`](https://www.torproject.org/download/)

---

### Step 2: **Install TOR Silently** 
`tor-browser-windows-x86_64-portable-14.0.1.exe /S` 

---

### Step 3: **Launch TOR Browser** 
Open the TOR browser from the folder located on the desktop.

---

### Step 4: **Connect to TOR and Browse Sites** 
⚠️ Onion links frequently change. The examples below may no longer be valid:

**Dread Forum:** `dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion`

**Dark Markets Forum:** `dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/DarkNetMarkets`

**Elysium Market:** `elysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad.top/login`

---

### Step 5: **Create a Suspicious File**
Add a few fake, illicit items to simulate suspicious behavior.
`tor-shopping-list.txt`

---

### Step 6: **Delete the File**
Remove `tor-shopping-list.txt` to simulate cleanup activity.

---

## TABLES USED TO DETECT IOCS
| **Parameter**       | **Description**                                                                                                                |
|---------------------|--------------------------------------------------------------------------------------------------------------------------------|
| **Table**           | `DeviceFileEvents`                                                                                                             |
| **Info**            | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table                                               |
| **Purpose**         | Used to detect TOR browser downloads, installation artifacts, and the creation/deletion of files like `tor-shopping-list.txt`. |

| **Parameter**       | **Description**                                                                              |
|---------------------|----------------------------------------------------------------------------------------------|
| **Table**           | `DeviceProcessEvents`                                                                        |
| **Info**            | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table             |
| **Purpose**         | Used to detect silent TOR installation and the execution of `tor.exe` and related processes. |
 
| **Parameter**       | **Description**                                                                                                                                    |
|---------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| **Name**            | `DeviceNetworkEvents`                                                                                                                              |
| **Info**            | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table                                                          |
| **Purpose**         | Used to detect TOR network activity, including connections from `tor.exe` or `firefox.exe` to known TOR ports (9001, 9030, 9040, 9050, 9051, 9150).|

---

## QUERIES USED
```kql
DeviceFileEvents
| where FileName  contains "tor"
| order by Timestamp desc
```

```kql
DeviceFileEvents
| where DeviceName == "willis-threat-h"
| where InitiatingProcessAccountName == "bwillis"
| where FileName  contains "tor"
| order by Timestamp desc
```

```kql
DeviceFileEvents
| where DeviceName == "willis-threat-h"
| where InitiatingProcessAccountName == "bwillis"
| where FileName  contains "tor"
| where Timestamp >= datetime(2025-07-05T00:58:17.8896593Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName
```

```kql
DeviceProcessEvents
| where DeviceName == "willis-threat-h"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
```

```kql
DeviceFileEvents
| where DeviceName == "willis-threat-h"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, FileName, SHA256, InitiatingProcessCommandLine
| order by Timestamp desc
```

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where DeviceName == "willis-threat-h"
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

```kql
DeviceFileEvents
| where FileName contains "shopping-list.txt"
| where DeviceName == "willis-threat-h"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, InitiatingProcessFileName, FolderPath, SHA256, FileSize
```

---

## CREATED BY
**Author**: `Briana Willis`<br>
**Contact**: [`https://www.linkedin.com/in/brianalwillis/`](https://www.linkedin.com/in/brianalwillis/)<br>
**Date**: `2025-07-05`

## VALIDATED BY
**Reviewer Name**:<br> 
**Reviewer Contact**:<br> 
**Validation Date**: 

---

## REVISION HISTORY
| **Version** | **Date**     | **Modified By**   |
|-------------|-------------------------------|--------------|-------------------|
| 1.0         | `2025-07-05` | `Briana Willis`   
