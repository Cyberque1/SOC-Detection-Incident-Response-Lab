# PowerShell Script Block Logging and Encoded Command Detection

## Objective

Correlate Sysmon process telemetry with PowerShell Script Block Logging to distinguish how PowerShell was launched from what PowerShell code actually executed.

## Environment and Tools

- Endpoint: `LAB-ENDPOINT-01`
- User context: `LAB-ENDPOINT-01\User1`
- Activity generated from normal, non-elevated PowerShell
- Telemetry: Sysmon Event ID `1` and PowerShell Event ID `4104`
- Analysis: PowerShell `Get-WinEvent` and structured XML parsing

## Logging Configuration

The PowerShell Operational log existed, but full Script Block Logging was not configured by policy. The policy was enabled by setting:

```text
EnableScriptBlockLogging = 1
```

Afterward, Event ID `4104` reliably recorded executed PowerShell script blocks.

## Detection / Investigation

### Plain Script-Block Test

A normal PowerShell session launched a child PowerShell process containing a harmless marker.

Sysmon Event ID `1` showed:

- child PID `972`
- parent PID `8000`
- `powershell.exe`
- command line containing the marker
- `IntegrityLevel: Medium`

PowerShell Event ID `4104` showed:

- `ProcessID: 972`
- readable script block containing `LAB8-4104-TEST`

The matching PID directly tied the created process to the code executed inside it.

### Encoded PowerShell Test

A harmless script was Base64-encoded and passed to a child PowerShell process with `-EncodedCommand`.

Sysmon Event ID `1` captured:

- `ProcessId: 3724`
- `ParentProcessId: 9320`
- `Image: powershell.exe`
- command line containing `-EncodedCommand` and Base64 data
- `IntegrityLevel: Medium`

PowerShell Event ID `4104` for the same PID `3724` exposed the readable script content:

```powershell
$encodedMarker="LAB8-ENCODED-TEST"; Write-Output $encodedMarker
```

## Correlation Analysis

```text
Parent PowerShell — PID 9320
        ↓
Child powershell.exe — PID 3724
        |
        +--> Sysmon Event ID 1
        |    -EncodedCommand <Base64>
        |
        +--> PowerShell Event ID 4104
             readable ScriptBlockText
```

The exercise demonstrated the complementary value of the two telemetry sources:

- **Sysmon Event ID 1:** executable, command line, user, parent process, integrity level, PID/ProcessGuid
- **PowerShell Event ID 4104:** PowerShell code that actually executed

Base64 is encoding, not encryption. The presence of `-EncodedCommand` is a useful triage signal, but it is not proof of malicious activity; the decoded code and surrounding context still require analysis.

## Correlated Finding

**Finding:** A normal-user PowerShell process launched a child PowerShell instance using `-EncodedCommand`. Sysmon identified the encoded invocation, while Event ID `4104` revealed the readable script executed by the same PID. The combined telemetry provided a stronger basis for PowerShell triage than either source alone.

## Skills Demonstrated

- PowerShell Script Block Logging configuration
- Event ID `4104` analysis
- Sysmon Event ID `1` analysis
- Encoded PowerShell triage
- PID-based cross-log correlation
- Parent-child process analysis
- Integrity-level interpretation
- Structured event XML parsing
- Context-based suspicious-command assessment
