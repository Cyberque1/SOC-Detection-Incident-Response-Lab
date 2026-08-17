# Sysmon Monitoring

## Objective

Use Sysmon telemetry to investigate process and network activity on the Windows endpoint.

## What Sysmon Does

Sysmon (System Monitor) records detailed Windows endpoint activity that can support security investigations. It does not automatically decide whether activity is malicious; analysts interpret the telemetry in context.

## Event ID 1 — Process Creation

Sysmon Event ID `1` records a process being created.

Useful fields include:

- `Image`
- `CommandLine`
- `ParentImage`
- `User`
- `ProcessId`
- `ParentProcessId`
- Hash information when configured

### Analyst Interpretation

The process name alone is often insufficient. Command-line arguments and parent-child process relationships provide important context.

Example:

```text
powershell.exe
```

is less informative than a full command line showing exactly how PowerShell was launched and what it executed.

## Event ID 3 — Network Connection

Sysmon Event ID `3` records network connection telemetry when enabled by the Sysmon configuration.

Useful fields include:

- `Image`
- `User`
- `Protocol`
- `SourceIp`
- `SourcePort`
- `DestinationIp`
- `DestinationPort`

## Basic Investigation Method

1. Identify the timestamp.
2. Identify the host.
3. Identify the user.
4. Identify the process.
5. Identify source and destination network information.
6. Determine the result or behavior.
7. Correlate related events into a timeline.

## Memory Recall

1. What does Sysmon Event ID 1 record?
2. What does Sysmon Event ID 3 record?
3. Why can the `CommandLine` field be more useful than the process name?
4. What fields would you inspect when analyzing a network connection?
5. Does Sysmon itself determine whether an event is malicious?
