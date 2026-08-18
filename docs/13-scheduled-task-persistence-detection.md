# Scheduled Task Persistence Detection

## Objective

Detect and investigate a benign Windows scheduled task configured to run at user logon, then correlate Windows Security auditing with Sysmon process telemetry to identify the process and privilege level responsible for creating the task.

## Environment and Telemetry

- Endpoint: `LAB-ENDPOINT-01`
- Test task: `\CyberLab13`
- Trigger: user logon
- Test action: `notepad.exe`
- Windows Security log: Event ID `4698`
- Sysmon Operational log: Event ID `1`

The activity was generated only inside the personally controlled lab.

## Detection Preparation

The `Other Object Access Events` audit subcategory initially showed `No Auditing`. Success auditing was enabled so Windows would record scheduled-task creation events.

After the change, the audit state showed:

```text
Other Object Access Events    Success
```

This established the Windows Security telemetry needed for the investigation.

## Privilege Comparison

The same scheduled-task creation technique was attempted from two PowerShell contexts.

### Non-elevated attempt

The first attempt was launched from normal PowerShell and failed with:

```text
ERROR: Access is denied.
```

The corresponding Sysmon Event ID `1` showed:

- `Image: C:\Windows\System32\schtasks.exe`
- `ProcessId: 2920`
- `User: LAB-ENDPOINT-01\User1`
- `IntegrityLevel: Medium`
- `ParentImage: powershell.exe`
- command line targeting the `CyberLab13` task

### Elevated attempt

The task was then created from Administrator PowerShell and succeeded.

The matching Sysmon Event ID `1` showed:

- `TimeCreated: 8/18/2026 2:13:27 PM`
- `UtcTime: 2026-08-18 18:13:27.332`
- `Image: C:\Windows\System32\schtasks.exe`
- `ProcessId: 9936`
- `ProcessGuid: {44acc921-a0c7-6a84-2805-000000000e00}`
- `User: LAB-ENDPOINT-01\User1`
- `IntegrityLevel: High`
- `ParentImage: powershell.exe`
- command line creating the `CyberLab13` logon task

This produced a clear privilege contrast:

```text
Medium integrity
      ↓
schtasks.exe
      ↓
Access denied

High integrity
      ↓
schtasks.exe
      ↓
Task creation succeeds
```

## Windows Security Evidence

Security Event ID `4698` was generated at the same second as the successful elevated `schtasks.exe` process.

Verified fields included:

- `Event ID: 4698`
- `Account Name: User1`
- `Account Domain: LAB-ENDPOINT-01`
- `Task Name: \CyberLab13`
- task XML containing a `LogonTrigger`
- task state enabled

The event proves that the scheduled task was created and preserves the task definition used for analyst review.

## Correlation

The successful Sysmon Event ID `1` and Security Event ID `4698` both occurred at approximately `2:13:27 PM`.

```text
Administrator PowerShell
        ↓
launches schtasks.exe
IntegrityLevel: High
PID 9936
        ↓
Sysmon Event ID 1
        ↓
Windows Security Event ID 4698
        ↓
\CyberLab13 created
        ↓
LogonTrigger → notepad.exe
```

The earlier medium-integrity attempt generated process telemetry but did not generate the successful task-creation event because Windows denied the operation.

## Analyst Finding

A scheduled task configured to execute at user logon was successfully created only after the task-creation process ran at high integrity. Sysmon identified the responsible `schtasks.exe` process, parent process, user, command-line context, and integrity level. Windows Security Event ID `4698` independently confirmed creation of `\CyberLab13` and exposed the task definition and logon trigger.

In a real investigation, scheduled-task creation should be evaluated in context rather than automatically labeled malicious. Analysts should review the creator process, user, integrity level, task trigger, executable/action, timing, and related activity to determine whether the task represents legitimate administration or persistence.

## Skills Demonstrated

- Windows advanced audit-policy validation
- Scheduled-task persistence analysis
- Windows Security Event ID `4698` interpretation
- Sysmon Event ID `1` process analysis
- Process privilege and integrity-level comparison
- Parent-child process investigation
- Cross-source event correlation
- Security timeline reconstruction
- Persistence triage and contextual analysis
