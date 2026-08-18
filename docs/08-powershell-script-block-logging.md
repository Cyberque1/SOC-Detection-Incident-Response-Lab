# PowerShell Script Block Logging and Encoded Command Detection

## Objective

Enable and verify PowerShell Script Block Logging, generate benign PowerShell activity, and correlate PowerShell Event ID `4104` with Sysmon Event ID `1` to understand both **what process ran** and **what PowerShell code actually executed**.

## Why This Matters

PowerShell is a legitimate administration tool but is also frequently abused by attackers. A SOC analyst needs to distinguish normal administrative use from suspicious behavior by correlating process telemetry, command lines, privilege level, and PowerShell script content.

This lab uses only harmless marker strings inside the personally controlled lab environment.

## Lab System

- Host under investigation: `LAB-ENDPOINT-01`
- User: `LAB-ENDPOINT-01\User1`
- Activity generated from normal, non-elevated PowerShell
- Sysmon investigation performed from Administrator PowerShell because the normal session received an unauthorized-access error when reading the protected Sysmon log

## Step 1 — Verify the PowerShell Operational Log

The PowerShell Operational log was checked with:

```powershell
Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' |
Select-Object LogName, IsEnabled, RecordCount
```

Verified state:

- `IsEnabled: True`
- `RecordCount: 508`

Existing historical Event ID `4104` records were present, but this did **not** prove that full Script Block Logging policy was currently enabled.

## Step 2 — Check Script Block Logging Policy

The policy path was queried:

```powershell
Get-ItemProperty `
  -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
  -ErrorAction SilentlyContinue |
Select-Object EnableScriptBlockLogging, EnableScriptBlockInvocationLogging
```

No output was returned, showing that full Script Block Logging was not configured by policy.

## Step 3 — Enable Script Block Logging

From Administrator PowerShell:

```powershell
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
```

```powershell
Set-ItemProperty `
  -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
  -Name EnableScriptBlockLogging `
  -Value 1
```

Verification returned:

```text
EnableScriptBlockLogging
------------------------
1
```

Invocation start/stop logging was intentionally not enabled because it was unnecessary for this exercise and would add extra noise.

## Step 4 — Benign Script-Block Test

A normal PowerShell session launched a child PowerShell process with a distinctive marker:

```powershell
powershell.exe -NoProfile -Command "`$labMarker='LAB8-4104-TEST'; Write-Output `$labMarker"
```

Expected and observed output:

```text
LAB8-4104-TEST
```

### PowerShell Event ID 4104

The PowerShell Operational log showed the executed child script block:

```powershell
$labMarker='LAB8-4104-TEST'; Write-Output $labMarker
```

Structured XML parsing showed:

- child `ProcessID: 972`
- parent PowerShell `ProcessID: 8000`
- child script block contained `LAB8-4104-TEST`

### Sysmon Event ID 1

The matching Sysmon process-creation event showed:

- `UtcTime: 2026-08-18 15:32:11.739`
- `ProcessId: 972`
- `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- command line containing `LAB8-4104-TEST`
- `User: LAB-ENDPOINT-01\User1`
- `IntegrityLevel: Medium`
- `ParentProcessId: 8000`
- `ParentImage: powershell.exe`

### Correlation Result

The same child PID `972` appeared in both:

- Sysmon Event ID `1`
- PowerShell Event ID `4104`

This directly correlated the process creation with the PowerShell code executed inside that process.

The `Medium` integrity level confirmed the activity came from a normal, non-elevated PowerShell session. This was an improvement over the earlier lab state in which PowerShell unintentionally opened elevated and child processes showed `High` integrity.

## Step 5 — Benign Encoded PowerShell Test

A harmless script was converted to Base64 and passed to PowerShell with `-EncodedCommand`:

```powershell
$script='$encodedMarker="LAB8-ENCODED-TEST"; Write-Output $encodedMarker'; $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script)); powershell.exe -NoProfile -EncodedCommand $encoded
```

Observed output:

```text
LAB8-ENCODED-TEST
```

> Base64 is encoding, not encryption. The presence of `-EncodedCommand` is a useful detection signal but does not by itself prove malicious activity.

## Step 6 — Sysmon View of the Encoded Command

The matching Sysmon Event ID `1` showed:

- `TimeCreated: 8/18/2026 11:42:31 AM`
- `UtcTime: 2026-08-18 15:42:31.559`
- `ProcessId: 3724`
- `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- command line containing `-NoProfile -EncodedCommand` followed by Base64 text
- `User: LAB-ENDPOINT-01\User1`
- `IntegrityLevel: Medium`
- `ParentProcessId: 9320`
- `ParentImage: powershell.exe`

From Sysmon alone, an analyst can identify that a normal-user PowerShell process launched another PowerShell process using an encoded command.

## Step 7 — PowerShell 4104 View of the Decoded Code

PowerShell Event ID `4104` showed the readable code that executed in the child process:

```powershell
$encodedMarker="LAB8-ENCODED-TEST"; Write-Output $encodedMarker
```

Structured XML parsing showed:

- `EventID: 4104`
- `ProcessID: 3724`
- decoded `ScriptBlockText` containing `LAB8-ENCODED-TEST`

The parent PowerShell process was PID `9320` and its 4104 record showed the code used to create the Base64 string and launch the encoded child process.

## Direct PID Correlation

```text
Parent PowerShell
PID 9320
        |
        | creates encoded command
        v
Child powershell.exe
PID 3724
        |
        +--> Sysmon Event ID 1
        |    -EncodedCommand <Base64>
        |
        +--> PowerShell Event ID 4104
             decoded ScriptBlockText
             $encodedMarker="LAB8-ENCODED-TEST"...
```

The same PID `3724` directly ties the encoded Sysmon process event to the decoded PowerShell script-block telemetry.

## Important Analyst Lessons

### Sysmon Event ID 1

Best for answering:

- What executable launched?
- What command line was supplied?
- Which user ran it?
- What was the integrity level?
- What parent process launched it?
- What was the PID / ProcessGuid?

### PowerShell Event ID 4104

Best for answering:

- What PowerShell code actually executed?
- What did an encoded or dynamically constructed command resolve to?
- Which PowerShell process executed that script block?

### Encoded Does Not Automatically Mean Malicious

`-EncodedCommand` can be used legitimately. Treat it as a reason to investigate, not as proof of compromise. Examine:

- decoded script content
- parent process
- user
- privilege level
- destination/network behavior
- persistence or follow-on actions
- timing and surrounding events

### Logging Your Own Investigation

PowerShell Script Block Logging also recorded the analyst's own `Get-WinEvent` investigation commands. This is expected. Analysts must distinguish investigative activity from the original activity under review.

### Permissions Lesson

The normal PowerShell session could query the PowerShell Operational log but received:

```text
Attempted to perform an unauthorized operation.
```

when reading the Sysmon Operational log. The Sysmon investigation was therefore performed from Administrator PowerShell while the test activity itself remained non-elevated.

## Detection Pattern

A useful triage pattern is:

```text
powershell.exe
        + command line contains -EncodedCommand
        |
        v
Inspect corresponding Event ID 4104
        |
        v
Review decoded ScriptBlockText
        |
        v
Correlate user + parent + integrity + PID + follow-on activity
        |
        v
Decide whether activity is benign, suspicious, or malicious
```

## Cleanup / Final State

No temporary listener or firewall rule was created in this lab.

Script Block Logging remains enabled intentionally because it improves future defensive visibility on `LAB-ENDPOINT-01`.

## Memory Recall

1. What does PowerShell Event ID `4104` record?
2. Why did historical 4104 events not prove the policy was currently enabled?
3. What registry value was used to enable Script Block Logging?
4. What does Sysmon Event ID `1` tell you that 4104 does not?
5. What does 4104 tell you that Sysmon Event ID `1` may not?
6. What did `IntegrityLevel: Medium` prove about the test process?
7. Why was Administrator PowerShell required to read the Sysmon log in this lab?
8. What PID correlated the first marker test across Sysmon and 4104?
9. What PID correlated the encoded-command test across Sysmon and 4104?
10. What does `-EncodedCommand` tell an analyst?
11. Why is Base64 not encryption?
12. Why should encoded PowerShell not automatically be labeled malicious?
13. Which telemetry source exposed the readable contents of the encoded command?
14. Which fields should be correlated before making a verdict?
15. Why did the analyst's own PowerShell investigation commands also appear as 4104 events?
