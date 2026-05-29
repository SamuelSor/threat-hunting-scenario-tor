# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" or "firefox in it and discovered what looks like the user "samhr" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `Tor Shopping List.txt` on the desktop at `2026-05-22T17:57:57.0767047Z`. These events began at `2026-05-22T17:43:35.8409475Z`.

**Query used to locate events:**

```kql
let TargetDevice = "threathuntsam1";
DeviceFileEvents
| where DeviceName == TargetDevice
| where TimeGenerated > ago(10d)
| where FileName has_any ("tor","firefox")
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
<img width="1450" height="468" alt="image" src="https://github.com/user-attachments/assets/16b8581d-229f-494a-bdc8-03af0984636c" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the strings "tor" or "firefox". Based on the logs returned, at `2026-05-22T17:47:17.6766897Z`, an employee on the "threathuntsam1" device ran the file `tor-browser-windows-x86_64-portable-15.0.14.exe` from their Downloads folder, using a command that triggered a silent installation: `/S`. The user account `samhr` also opened the TOR browser `(tor.exe)` at `2026-05-22T17:48:07.3538238Z` and other FireFox `(firefox.exe)` instances soon after the TOR browser was installed.

**Query used to locate event:**

```kql
let TargetDevice = "threathuntsam1";
DeviceProcessEvents
| where DeviceName == TargetDevice
| where TimeGenerated > ago(10d)
| where ProcessCommandLine has_any ("firefox", "tor")
| order by TimeGenerated desc
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, SHA256, ProcessCommandLine

```
<img width="1481" height="499" alt="image" src="https://github.com/user-attachments/assets/9b2a6a2d-30da-4cfd-85e2-2363a768dc82" />

---

### 3. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection. At `2026-05-22T17:48:51.3406778Z`, an employee on the "threathuntsam1" device successfully established a connection to the remote IP address `188.245.203.234` on port `9001` at the URL `https://www.3rilcmlyneuw.com`. Port `9001` is known to be used by the TOR browser. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\samhr\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443` as well.

**Query used to locate events:**

```kql
let TargetDevice = "threathuntsam1";
let TimeInitiated = datetime(2026-05-22T17:47:17.6766897Z);
DeviceNetworkEvents
| where DeviceName == TargetDevice
| where Timestamp between ((TimeInitiated - 2m) .. (TimeInitiated + 10m))
| where InitiatingProcessCommandLine has_any("firefox", "tor")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="1415" height="505" alt="image" src="https://github.com/user-attachments/assets/f82e7914-6be7-4cfb-bafa-2ae576c4e8f8" />

---

## Chronological Timeline of TOR Browser Activity

## May 22, 2026

### 1:43:35 PM — TOR Browser Installer Downloaded

* User `samhr` downloaded the TOR Browser installer onto endpoint `threathuntsam1`.
* File downloaded:

  * `tor-browser-windows-x86_64-portable-15.0.14.exe`
* File location:

  * `C:\Users\SamHR\Downloads\tor-browser-windows-x86_64-portable-15.0.14.exe`

---

### 1:47:17 PM — Silent TOR Browser Installation Executed

* The TOR Browser installer was executed using a silent installation command.
* Command executed:

  ```powershell
  tor-browser-windows-x86_64-portable-15.0.14.exe /S
  ```
* The `/S` flag indicates the installation was performed without user prompts or visible interaction.

---

### 1:47:18 PM — TOR Browser Files Created

* TOR Browser application files were created on the endpoint following installation.
* Key files observed:

  * `firefox.exe`
  * `tor.exe`
* Example file paths:

  * `C:\Users\SamHR\Desktop\Tor Browser\Browser\firefox.exe`
  * `C:\Users\SamHR\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

### 1:47:32 PM — TOR Browser Launched

* Multiple `firefox.exe` processes associated with the TOR Browser were executed.
* Observed process activity included:

  ```powershell
  "firefox.exe" -contentproc -isForBrowser
  ```
* This confirmed active execution and initialization of the TOR Browser.

---

### 1:47:58 PM — TOR Network Activity Detected

* Initial TOR-related network communications were observed.
* Activity included:

  * `ListeningConnectionCreated`
  * `ConnectionSuccess`
* Connections were made to localhost (`127.0.0.1`), consistent with TOR proxy/tunneling behavior.

---

### 1:48:10 PM — TOR Browser Accessed TOR-Related Websites

* The endpoint established outbound connections to TOR-associated websites.
* Observed URL:

  * `https://www.ccnwwa4ozflajlpzdhz.com`
* Investigation data showed the user connected to at least four TOR-related websites during the session.

---

### 1:57:57 PM — “Tor Shopping List” File Created

* A text document named `Tor Shopping List.txt` was created by user `samhr`.
* File path:

  * `C:\Users\SamHR\Documents\Tor Shopping List.txt`
* The file name suggests possible activity or planning associated with TOR usage.

---

### 1:58:50 PM — TOR Executables Deleted

* TOR-related executable files were deleted from the endpoint shortly after use.
* Deleted files included:

  * `tor.exe`
  * `firefox.exe`

---

### 1:58:59 PM — TOR Installer Deleted

* The original TOR Browser installer was deleted from the Downloads directory.
* Deleted file:

  * `tor-browser-windows-x86_64-portable-15.0.14.exe`

---

## Summary

The threat hunt confirmed that user `samhr` downloaded, installed, and actively used the TOR Browser on endpoint `threathuntsam1` on May 22, 2026. Investigation data from `DeviceFileEvents` and `DeviceProcessEvents` showed the TOR Browser installer was downloaded and executed using a silent installation command `(/S)`, followed by the creation and execution of TOR-related files including `firefox.exe` and `tor.exe`. Network telemetry from `DeviceNetworkEvents` confirmed TOR-related communications and outbound connections to multiple TOR-associated websites, including `https://www.ccnwwa4ozflajlpzdhz.com`. During the same session, the user created a text document named `Tor Shopping List.txt`, which may indicate activity associated with TOR usage. Shortly afterward, TOR executables and the original installer were deleted from the endpoint, suggesting possible cleanup or concealment activity following browser use. 

---

## Response Taken

TOR usage was confirmed on the endpoint `threathuntsam1` by the user `samhr`. The device was isolated, and the user's direct manager was notified.

---
