# Process-to-Network Correlation

## Objective

Generate a benign outbound connection from a known Windows process, then correlate Sysmon Event ID `1` (Process Create) with Sysmon Event ID `3` (Network Connection) to reconstruct a multi-event timeline.

## Why This Matters

SOC analysts rarely investigate one event in isolation. A process may start with a particular command line and then communicate with another system. Correlating process and network telemetry helps answer both **what ran** and **what it connected to**.

## Lab Scope

This exercise was performed only inside the personally controlled lab environment.

- Windows endpoint: `LAB-ENDPOINT-01`
- Windows IP: `192.168.64.2`
- Kali test system: `LAB-KALI-01`
- Kali IP: `192.168.64.3`
- Test service: TCP `8080`

## Workflow

1. Run a temporary Python HTTP server on Kali.
2. Verify that Kali is actually listening on the expected TCP port.
3. Launch `curl.exe` from Windows PowerShell.
4. Confirm the HTTP request reaches Kali and returns HTTP `200`.
5. Locate Sysmon Event ID `1` for the `curl.exe` process creation.
6. Locate Sysmon Event ID `3` for the outbound TCP connection.
7. Correlate process ID, command line, addresses, port, and timestamps.
8. Document findings and clean up the temporary server.

## Step 1 — Kali HTTP Server

The active server was:

```bash
python3 -m http.server 8080 --bind 192.168.64.3
```

Verified server output:

```text
Serving HTTP on 192.168.64.3 port 8080 ...
```

### Listener Verification

A second Kali terminal was used to verify the socket:

```bash
ss -ltn | grep ':8080'
```

Verified result showed a TCP listener on:

```text
192.168.64.3:8080
```

### Troubleshooting Lesson

The first Windows request was attempted against TCP `8000` and failed:

```text
curl: (7) Failed to connect ... Could not connect to server
```

Windows could still ping Kali successfully, which showed that basic IP connectivity was working. A local Kali `curl` test to port `8000` also failed, and `ss` showed no listener on that port.

The actual Python server was listening on port `8080`. Verifying the listener with `ss` identified the mismatch before the test was retried.

Troubleshooting sequence:

```text
Connection failed
      ↓
Test basic reachability with ping
      ↓
Verify listening socket with ss
      ↓
Confirm correct IP + port
      ↓
Retry application connection
```

## Step 2 — Generate Windows Process and Connection

From Windows PowerShell:

```powershell
curl.exe http://192.168.64.3:8080/
```

Windows received the HTML directory listing from the Kali Python server.

> Portfolio note: serving a user home directory can reveal filenames. Future screenshots should use a dedicated empty lab directory rather than exposing unnecessary file names.

## Step 3 — External Confirmation on Kali

The Kali server recorded:

```text
192.168.64.2 - - [17/Aug/2026 23:51:34] "GET / HTTP/1.1" 200 -
```

Interpretation:

- Source client: `192.168.64.2` (`LAB-ENDPOINT-01`)
- Request: `GET /`
- Protocol: HTTP/1.1
- Result: HTTP `200` success
- Local server time: `23:51:34`

This independently confirmed that the Windows request reached Kali and was successfully served.

## Step 4 — Sysmon Event ID 1: Process Creation

The matching Event ID `1` showed:

- `TimeCreated: 8/17/2026 11:51:34 PM`
- `UtcTime: 2026-08-18 03:51:34.790`
- `ProcessId: 10740`
- `ProcessGuid: {44acc921-d6c6-6a83-4003-000000000b00}`
- `Image: C:\Windows\System32\curl.exe`
- `CommandLine: "C:\WINDOWS\System32\curl.exe" http://192.168.64.3:8080/`
- `User: LAB-ENDPOINT-01\User1`
- `IntegrityLevel: High`
- `ParentProcessId: 8476`
- `ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

### Interpretation

PowerShell launched `curl.exe` with a command line explicitly targeting the Kali HTTP server.

```text
powershell.exe (PID 8476)
        ↓
creates
        ↓
curl.exe (PID 10740)
        ↓
command line targets 192.168.64.3:8080
```

## Step 5 — Sysmon Event ID 3: Network Connection

The matching Event ID `3` showed:

- `UtcTime: 2026-08-18 03:51:34.874`
- `ProcessId: 10740`
- `ProcessGuid: {00000000-0000-0000-0000-000000000000}`
- `Image: <unknown process>`
- `Protocol: tcp`
- `Initiated: true`
- `SourceIp: 192.168.64.2`
- `SourcePort: 53957`
- `DestinationIp: 192.168.64.3`
- `DestinationPort: 8080`

### Interpretation

The Windows endpoint initiated an outbound TCP connection from temporary source port `53957` to Kali on TCP `8080`.

`Initiated: true` confirms that the monitored Windows side initiated the connection.

## Step 6 — Structured Correlation Query

Rather than relying only on rendered Event Viewer text, PowerShell was used to parse Sysmon's structured XML fields and select records with `ProcessId` `10740`.

The query returned both:

```text
Event ID 1
ProcessId: 10740
Image: C:\Windows\System32\curl.exe
CommandLine: curl.exe http://192.168.64.3:8080/
```

and:

```text
Event ID 3
ProcessId: 10740
DestinationIp: 192.168.64.3
DestinationPort: 8080
```

This placed the process-creation and network events in one correlated view.

## Timestamp Correlation

The Sysmon payload timestamps were:

```text
Event ID 1 UtcTime: 03:51:34.790
Event ID 3 UtcTime: 03:51:34.874
```

The difference is approximately **84 milliseconds**.

This is stronger timing evidence than the Event Viewer `TimeCreated` display alone. In this capture, Event Viewer showed the network event several seconds later even though Sysmon's internal `UtcTime` placed the connection only milliseconds after process creation.

### Analyst Lesson

When precision matters, distinguish between:

- event payload time (`UtcTime`), and
- the time the event record is displayed/logged by the viewer.

The event payload can provide the more precise activity timeline.

## Incomplete Telemetry Lesson

The Event ID `3` record contained:

```text
ProcessGuid: {00000000-0000-0000-0000-000000000000}
Image: <unknown process>
```

Therefore, `ProcessGuid` and `Image` could **not** be used as correlation fields for this particular network event.

The correlation remained strong because the following fields aligned:

- same `ProcessId: 10740`
- exact destination `192.168.64.3:8080`
- matching TCP direction (`Initiated: true`)
- matching known command line
- Sysmon payload timestamps only ~84 ms apart
- independent Kali HTTP `200` log at the same second

An analyst should use the best available fields rather than assuming every telemetry record will contain complete metadata.

## Reconstructed Timeline

```text
23:51:34 local / 03:51:34.790 UTC
PowerShell launches curl.exe
Sysmon Event ID 1
PID 10740
        ↓
~84 ms later
03:51:34.874 UTC
Sysmon Event ID 3
PID 10740
192.168.64.2:53957 → 192.168.64.3:8080
        ↓
Kali HTTP server receives
GET / HTTP/1.1
        ↓
HTTP 200 success
```

## Analyst Findings

- **Process executed:** `curl.exe`
- **Command line:** `curl.exe http://192.168.64.3:8080/`
- **User:** `LAB-ENDPOINT-01\User1`
- **Parent process:** `powershell.exe`
- **Process ID:** `10740`
- **Event ID 1 ProcessGuid:** `{44acc921-d6c6-6a83-4003-000000000b00}`
- **Network destination:** `192.168.64.3`
- **Destination port:** TCP `8080`
- **Source port:** `53957`
- **Sysmon events used:** `1` and `3`
- **External confirmation:** Kali HTTP server logged `GET / HTTP/1.1` with response `200`
- **Conclusion:** A PowerShell-launched `curl.exe` process initiated the verified TCP/HTTP connection from Windows to the Kali server. The process and network records were correlated by PID, destination, direction, command line, and tightly aligned Sysmon payload timestamps.

## Cleanup

Stop the temporary Kali HTTP server with:

```text
Ctrl+C
```

Verify the listener is gone:

```bash
ss -ltn | grep ':8080'
```

No output indicates that the temporary listener is no longer active.

## Memory Recall

1. What does Sysmon Event ID `1` record?
2. What does Sysmon Event ID `3` record?
3. What was the parent process of `curl.exe`?
4. What did the `curl.exe` command line reveal?
5. What did `Initiated: true` mean?
6. Which destination IP and port did `curl.exe` contact?
7. Why was PID `10740` useful for correlation?
8. Why could `ProcessGuid` not be used to correlate Event ID 3 in this capture?
9. What external evidence proved the request actually reached Kali?
10. What did HTTP status `200` mean?
11. Why did the initial TCP `8000` attempt fail?
12. What command verified the Kali listening socket?
13. Why is `ping` success not enough to prove an application port is reachable?
14. Why are structured XML fields useful when querying Windows events?
15. What was the approximate time difference between Event ID 1 and Event ID 3 using Sysmon `UtcTime`?
16. Why can event payload time be more useful than Event Viewer display time for precise correlation?
17. Why should analysts correlate multiple fields instead of depending on one identifier?
