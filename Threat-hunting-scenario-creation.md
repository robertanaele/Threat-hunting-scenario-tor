# Scenario Creation: Unauthorized TOR Usage

## Objective
This document outlines the steps taken to generate logs and Indicators of Compromise (IoCs) for a threat-hunting exercise involving unauthorized TOR Browser usage.

---

## Steps the "Bad Actor" Took to Create Logs
1. **Download the TOR browser installer** from: https://www.torproject.org/download/
2. **Silently install the TOR browser** using the following command:
   ```cmd
   tor-browser-windows-x86_64-portable-15.0.9.exe /S
   ```
3. **Launch the TOR browser** from the folder extracted to the desktop.
4. **Establish TOR network activity** by connecting to the TOR network and browsing several sites.
   - **Note:** Onion links change frequently. Browsing any site while connected to TOR should still generate the required logs.
   - Example site visited: `elysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad.top/login`
5. **Create a file** on the desktop named `tor-shopping-list.txt` and add a few fake illicit items.
6. **Delete the file** to simulate cleanup or anti-forensics behavior.

---

## Tables Used to Detect IoCs

| Table | Purpose | Documentation |
|-------|---------|---------------|
| **DeviceFileEvents** | Detects TOR downloads, installation artifacts, and creation/deletion of the shopping list file. | [Microsoft Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **DeviceProcessEvents** | Detects silent installation activity and execution of `tor.exe` or `firefox.exe`. | [Microsoft Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **DeviceNetworkEvents** | Detects TOR-related network traffic over known relay and proxy ports. | [Microsoft Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |

---

## Related Queries

### 1. Detect TOR Installer Download
```kql
DeviceFileEvents
| where FileName startswith "tor-browser"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
```

### 2. Detect TOR Browser Silent Installation
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.9.exe /S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```

### 3. Detect TOR File Artifacts on Disk
```kql
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine
```

### 4. Detect TOR Browser Execution
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine
```

### 5. Detect Active TOR Network Connections
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 443)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### 6. Detect Shopping List File Creation or Deletion
```kql
DeviceFileEvents
| where FileName contains "shopping-list.txt"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
```

---

## Metadata
- **Original Author**: Robert Anaele
- **Author Contact**: [LinkedIn](https://www.linkedin.com/in/robert14786/)
- **Modified By**: Robert Anaele
- **Date**: April 2026

---

## Revision History

| Version | Changes | Date | Modified By |
|---------|---------|------|-------------|
| 1.0 | Initial draft | April 2026 | Robert Anaele |
