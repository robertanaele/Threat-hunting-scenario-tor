```markdown
# Threat-hunting-scenario-tor

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage (win-client-01)

- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

---

## Platforms and Languages Leveraged
- Windows 10 Virtual Machine (Microsoft Azure)
- Microsoft Defender for Endpoint (EDR)
- Kusto Query Language (KQL)
- TOR Browser (Portable Executable Analysis)

---

## Scenario

Management suspected potential unauthorized use of TOR Browser on endpoint **win-client-01** after observing unusual encrypted outbound traffic and suspected connections to anonymization infrastructure. The objective of this investigation was to determine whether TOR Browser was installed or executed, identify associated network activity, and reconstruct a timeline of user behavior for risk assessment.

---

## High-Level TOR-Related IoC Discovery Plan

- Query `DeviceFileEvents` for TOR-related executables or artifacts.
- Query `DeviceProcessEvents` for execution, installation, and browser launch activity.
- Query `DeviceNetworkEvents` for outbound TOR-related traffic (known ports and relay behavior).
- Correlate process execution with network activity and file system changes.

---

# Steps Taken

---

## 1. Searched the `DeviceFileEvents` Table

Searched for any file containing the string **"tor"** under user activity for **jameslee** on **win-client-01**.

### Findings:
- TOR-related installer execution initiated file creation and extraction activity.
- Multiple TOR-related files were copied to the Desktop.
- A file named **`tor-shipping-list.txt`** was created on:
- **Timestamp:** `2026-04-13T01:08:15Z`

### Query Used:

```kql
DeviceFileEvents
| where DeviceName == "win-client-01"
| where InitiatingProcessAccountName == "jameslee"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-04-13T01:08:15Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc
```

---

## 2. Searched the `DeviceProcessEvents` Table (Silent Installation)

Searched for execution of:

`tor-browser-windows-x86_64-portable-15.0.9.exe /S`

### Findings:

- User **jameslee** executed the TOR installer in **silent mode**
- Installation occurred with no visible UI or prompts
- **Timestamp:** `2026-04-13T01:08:15Z`

### Query Used:

```kql
DeviceProcessEvents
| where DeviceName == "win-client-01"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.9.exe /S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```

---

## 3. Searched for TOR Browser Execution

Searched for process execution indicating TOR Browser launch activity.

### Findings:

- TOR Browser was actively launched on:
- **Timestamp:** `2026-04-12T21:14:05Z`
- Processes observed:
  - `firefox.exe`
  - `tor.exe`

### Interpretation:

- Confirms TOR Browser was **successfully executed prior to installation event**

### Query Used:

```kql
DeviceProcessEvents
| where DeviceName == "win-client-01"
| where ProcessCommandLine has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine
| order by Timestamp desc
```

---

## 4. Searched the `DeviceNetworkEvents` Table (TOR Network Traffic)

Searched for outbound traffic associated with TOR-related processes.

### Findings:

- **Timestamp:** `2026-04-12T21:15:06Z`
- **Remote IP:** `69.12.83.97`
- **Remote Port:** `9001`
- **Process:** `tor.exe`
- Additional encrypted traffic observed over port **443**

### Interpretation:

- Confirms active participation in TOR network relay communication

### Query Used:

```kql
DeviceNetworkEvents
| where DeviceName == "win-client-01"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 443)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
         InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

---

# Chronological Event Timeline

---

## 1. TOR Browser Execution

- **Timestamp:** `2026-04-12T21:14:05Z`
- User **jameslee** launched TOR Browser.
- Processes spawned:
  - `firefox.exe`
  - `tor.exe`

**Outcome:** TOR Browser successfully started.

---

## 2. TOR Network Communication Established

- **Timestamp:** `2026-04-12T21:15:06Z`
- `tor.exe` established outbound connection:
  - IP: `69.12.83.97`
  - Port: `9001`
- Additional encrypted HTTPS traffic observed (port 443)

**Outcome:** Active TOR network participation confirmed.

---

## 3. Silent TOR Installation Executed

- **Timestamp:** `2026-04-13T01:08:15Z`
- Execution of:

  ```text
  tor-browser-windows-x86_64-portable-15.0.9.exe /S
  ```

**Outcome:**

- Silent installation performed
- No user interaction or UI prompts observed

---

## 4. TOR File Deployment on Desktop

- **Timestamp:** `2026-04-13T01:08:15Z`
- Multiple TOR-related files created/copied to Desktop
- File created:
  - `tor-shipping-list.txt`

**Outcome:** Portable TOR bundle extracted and staged locally.

---

# Chronological Event Timeline (Summary View)

| Time                 | Event                                           |
|----------------------|-------------------------------------------------|
| 2026-04-12 21:14:05Z | TOR Browser launched (`firefox.exe`, `tor.exe`) |
| 2026-04-12 21:15:06Z | TOR network connection established (port 9001)  |
| 2026-04-13 01:08:15Z | Silent TOR installer executed (`/S`)            |
| 2026-04-13 01:08:15Z | TOR files extracted to Desktop                  |

---

# Summary

The user **jameslee** on endpoint **win-client-01** demonstrated confirmed TOR activity including execution, network communication, and silent installation of the TOR Browser. Initial usage occurred on April 12, 2026, with active TOR network participation observed via encrypted connections and relay communication. Subsequently, a silent installation of the TOR Browser portable executable was performed on April 13, 2026, resulting in file extraction and staging of TOR-related artifacts on the Desktop.

---

# Response Taken

- TOR usage was confirmed on endpoint **win-client-01**
- Activity was escalated for review due to anonymization tool usage and silent installation behavior
- Endpoint activity should be assessed for policy violation and potential unauthorized anonymized browsing
```

If you want, I can also:
- clean up the formatting for a more professional GitHub README
- add badges, table of contents, and sections
- create a matching `threat-hunting-scenario-tor-event-creation.md` file in Markdown too
