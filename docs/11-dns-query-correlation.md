# DNS Query Detection and Process Correlation

## Objective

Generate a controlled DNS resolution from `LAB-ENDPOINT-01`, capture the activity with Sysmon Event ID `22`, and correlate the DNS event with Sysmon Event ID `1` to identify the process responsible for the query.

## Environment and Tools

- Endpoint: `LAB-ENDPOINT-01`
- User: `LAB-ENDPOINT-01\User1`
- Telemetry: Sysmon Event IDs `1` and `22`
- Test domain: `example.com`
- Process used for the verified DNS event: `PING.EXE`
- Investigation: PowerShell `Get-WinEvent`

## Detection and Investigation

Sysmon DNS Query telemetry was already enabled in the active configuration.

An initial `nslookup.exe example.com` successfully resolved the domain, but a direct Event ID `22` search for `example.com` returned no matching event. Rather than assuming the sensor was broken, recent Event ID `22` records were reviewed without the domain filter. This confirmed that Sysmon DNS telemetry was active for other processes.

A second controlled lookup was generated with:

```powershell
ping.exe example.com -n 1
```

The command resolved `example.com` and successfully contacted `172.66.147.243`.

## Sysmon Event ID 22 — DNS Query

The matching Event ID `22` contained:

- `UtcTime: 2026-08-18 17:44:44.331`
- `ProcessId: 9712`
- `ProcessGuid: {44acc921-9a0c-6a84-fd04-000000000e00}`
- `QueryName: example.com`
- `QueryStatus: 0`
- `Image: C:\Windows\System32\PING.EXE`
- `User: LAB-ENDPOINT-01\User1`
- Query results included `172.66.147.243` and `104.20.23.154` plus IPv6 addresses

`QueryStatus: 0` indicated a successful DNS resolution.

## Sysmon Event ID 1 — Process Creation

The corresponding Event ID `1` showed:

- `UtcTime: 2026-08-18 17:44:44.294`
- `ProcessId: 9712`
- `ProcessGuid: {44acc921-9a0c-6a84-fd04-000000000e00}`
- `Image: C:\Windows\System32\PING.EXE`
- `CommandLine: "C:\WINDOWS\System32\PING.EXE" example.com -n 1`
- `User: LAB-ENDPOINT-01\User1`
- `IntegrityLevel: Medium`
- `ParentProcessId: 9304`
- `ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

## Correlation

The process-creation and DNS events shared both:

- `ProcessId: 9712`
- `ProcessGuid: {44acc921-9a0c-6a84-fd04-000000000e00}`

The Sysmon UTC timestamps were approximately **37 milliseconds apart**:

```text
Event ID 1:  17:44:44.294
Event ID 22: 17:44:44.331
```

Reconstructed activity:

```text
powershell.exe
      ↓
launches PING.EXE
PID 9712
      ↓
Sysmon Event ID 1
      ↓
DNS query for example.com
      ↓
Sysmon Event ID 22
      ↓
resolved IP addresses
```

## Findings

A normal-user `PING.EXE` process launched by PowerShell performed a DNS lookup for `example.com`. Sysmon Event ID `22` captured the queried domain and returned addresses, while Event ID `1` provided the process command line, parent process, user, integrity level, PID, and ProcessGuid. Matching PID and ProcessGuid, along with a ~37 ms timestamp gap, directly correlated process execution with DNS activity.

The exercise also demonstrated that telemetry coverage should be validated rather than assumed. The initial `nslookup.exe` resolution did not produce the expected domain-specific Event ID `22`, while a separate `PING.EXE` lookup did. Reviewing broader Event ID `22` activity confirmed the sensor was operational before changing configuration.

## Skills Demonstrated

- Sysmon Event ID `22` DNS-query analysis
- Process-to-DNS correlation using Sysmon Event IDs `1` and `22`
- PID and ProcessGuid correlation
- DNS result interpretation
- Parent-child process analysis
- Timeline reconstruction using precise UTC timestamps
- Telemetry validation and troubleshooting
- PowerShell event-log querying
