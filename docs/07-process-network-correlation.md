# Process-to-Network Correlation

## Objective

Correlate Windows process-creation and network-connection telemetry to prove which process initiated a specific outbound connection.

## Environment and Tools

- Windows endpoint: `LAB-ENDPOINT-01` — `192.168.64.2`
- Kali server: `LAB-KALI-01` — `192.168.64.3`
- Test service: HTTP over TCP/8080
- Tools: PowerShell, `curl.exe`, Python HTTP server, Sysmon, PowerShell XML event parsing

## Detection / Investigation

A temporary Python HTTP server was started on Kali at `192.168.64.3:8080`. Windows then generated the controlled request:

```powershell
curl.exe http://192.168.64.3:8080/
```

Kali independently recorded:

```text
192.168.64.2 - - [17/Aug/2026 23:51:34] "GET / HTTP/1.1" 200 -
```

The Windows Sysmon log was searched for the matching process-creation and network-connection records.

## Evidence

### Sysmon Event ID 1 — Process Create

- `UtcTime: 2026-08-18 03:51:34.790`
- `ProcessId: 10740`
- `ProcessGuid: {44acc921-d6c6-6a83-4003-000000000b00}`
- `Image: C:\Windows\System32\curl.exe`
- `CommandLine: curl.exe http://192.168.64.3:8080/`
- `User: LAB-ENDPOINT-01\User1`
- `ParentImage: powershell.exe`

### Sysmon Event ID 3 — Network Connection

- `UtcTime: 2026-08-18 03:51:34.874`
- `ProcessId: 10740`
- `Protocol: tcp`
- `Initiated: true`
- `SourceIp: 192.168.64.2`
- `SourcePort: 53957`
- `DestinationIp: 192.168.64.3`
- `DestinationPort: 8080`

The Sysmon payload timestamps were approximately **84 milliseconds apart**.

## Correlation Analysis

```text
powershell.exe
      ↓
curl.exe — PID 10740
      ↓
Sysmon Event ID 1
command line targets 192.168.64.3:8080
      ↓  ~84 ms
Sysmon Event ID 3
192.168.64.2:53957 → 192.168.64.3:8080
      ↓
Kali HTTP log
GET / HTTP/1.1 → 200
```

The Event ID `3` record contained an unknown image and a zeroed ProcessGuid, so those fields could not be used for correlation. Instead, the investigation relied on multiple aligned fields:

- same PID `10740`
- exact destination IP and port
- outbound direction (`Initiated: true`)
- Event ID `1` command line
- tightly aligned UTC timestamps
- independent HTTP-server evidence

This demonstrated how to continue an investigation when one telemetry source contains incomplete metadata.

## Correlated Finding

**Finding:** PowerShell launched `curl.exe` as PID `10740`, and that process initiated the verified TCP connection from `LAB-ENDPOINT-01` to `LAB-KALI-01` on TCP/8080. Sysmon Event IDs `1` and `3`, combined with the Kali HTTP `200` log, established the process-to-network relationship.

## Skills Demonstrated

- Sysmon Event IDs `1` and `3`
- Parent-child process analysis
- Process-to-network correlation
- PID and timestamp correlation
- Structured Windows-event XML parsing
- Timeline reconstruction using UTC timestamps
- Validation with an independent network-service log
- Investigation of incomplete telemetry
