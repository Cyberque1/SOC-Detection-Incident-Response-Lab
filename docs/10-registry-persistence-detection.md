# Registry Persistence Detection

## Objective

Detect and investigate a benign Windows startup persistence mechanism by monitoring the current user's `Run` registry key with Sysmon, then correlate the registry modification to the process that created it.

## Environment and Tools

- `LAB-ENDPOINT-01` — Windows 11 monitored endpoint
- Sysmon
- Windows PowerShell
- Sysmon Event ID `1` — Process Create
- Sysmon Event ID `13` — Registry Value Set

All activity was generated inside the personally controlled lab environment.

## Detection Configuration

The active Sysmon configuration initially collected process, network, DNS, and file-create telemetry but did not include registry events.

A targeted registry rule was added rather than enabling broad registry collection:

```xml
<RegistryEvent onmatch="include">
  <TargetObject condition="contains">\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
</RegistryEvent>
```

After validation and application, `sysmon -c` confirmed `RegistryEvent` monitoring was active for the Windows `Run` path.

This approach focuses collection on a persistence-relevant location while reducing unnecessary registry-event noise.

## Controlled Activity

A benign current-user startup value was created:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\CyberLab10
Value: notepad.exe
```

The test value represented a common logon-startup mechanism without launching a malicious payload.

## Sysmon Event ID 13 — Registry Value Set

The primary registry event showed:

- `EventType: SetValue`
- `ProcessId: 4612`
- `ProcessGuid: {44acc921-95a3-6a84-e104-000000000e00}`
- `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- `TargetObject: HKU\<user-SID>\Software\Microsoft\Windows\CurrentVersion\Run\CyberLab10`
- `Details: notepad.exe`
- `User: LAB-ENDPOINT-01\User1`

Sysmon represented the current user's registry hive under `HKEY_USERS` with the user's SID rather than the `HKCU` alias used when the value was created.

A second Event ID `13` involving `sihost.exe` and a related `RunNotification` path also contained the test marker. The PowerShell event modifying the exact `Run\CyberLab10` value was identified as the primary evidence rather than assuming every matching record represented the original persistence action.

## Sysmon Event ID 1 — Process Creation

The matching process-creation event showed:

- `TimeCreated: 8/18/2026 1:25:55 PM`
- `UtcTime: 2026-08-18 17:25:55.398`
- `ProcessId: 4612`
- `ProcessGuid: {44acc921-95a3-6a84-e104-000000000e00}`
- `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- `User: LAB-ENDPOINT-01\User1`
- `IntegrityLevel: Medium`
- `ParentProcessId: 5892`
- `ParentImage: C:\Windows\explorer.exe`

## Correlation

Event ID `1` and Event ID `13` contained the same PID and ProcessGuid:

```text
explorer.exe
      ↓
powershell.exe
PID 4612
ProcessGuid {44acc921-95a3-6a84-e104-000000000e00}
      ↓
Sysmon Event ID 13
      ↓
CurrentVersion\Run\CyberLab10
      ↓
notepad.exe
```

This directly tied the registry modification to a specific normal-user PowerShell process.

## Analyst Finding

A medium-integrity PowerShell process launched by `explorer.exe` modified the current user's Windows `Run` key and created a startup value named `CyberLab10` pointing to `notepad.exe`. Sysmon Event IDs `1` and `13` were correlated using both `ProcessId` and `ProcessGuid` to identify the responsible process and the exact registry value written.

The existence of a `Run`-key entry is not automatically malicious. In an investigation, the next steps would be to evaluate the referenced executable, user context, parent process, timing, file reputation, network activity, persistence behavior, and surrounding telemetry before assigning a verdict.

## Skills Demonstrated

- Targeted Sysmon registry-event configuration
- Windows registry persistence analysis
- Sysmon Event ID `13` interpretation
- Process-to-registry correlation with Event ID `1`
- PID and ProcessGuid correlation
- Parent-process and integrity-level analysis
- Distinguishing primary evidence from related background telemetry
- Evidence-based SOC investigation and documentation
