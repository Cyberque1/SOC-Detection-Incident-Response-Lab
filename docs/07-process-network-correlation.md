# Process-to-Network Correlation

## Objective

Generate a benign outbound network connection from a known Windows process, then correlate Sysmon Event ID `1` (Process Create) with Sysmon Event ID `3` (Network Connection) to reconstruct a simple multi-event timeline.

## Why This Matters

SOC analysts rarely investigate one event in isolation. A suspicious process may start, launch with a particular command line, and then communicate with a remote system. Correlating process and network telemetry helps answer both **what ran** and **what it connected to**.

## Lab Scope

This exercise is performed only inside the personally controlled lab environment.

- Windows endpoint: `LAB-ENDPOINT-01`
- Kali test system: `LAB-KALI-01`
- Expected Windows IP: `192.168.64.2`
- Expected Kali IP: `192.168.64.3`
- Test service port: TCP `8000`

> Re-verify addresses before running the exercise if either VM has restarted or changed networks.

## Planned Workflow

1. Start a temporary HTTP server on Kali using Python.
2. Launch a new `curl.exe` process on Windows that requests the Kali HTTP server.
3. Confirm the HTTP request reaches Kali.
4. Locate the matching Sysmon Event ID `1` for `curl.exe`.
5. Locate the matching Sysmon Event ID `3` for the network connection.
6. Correlate process, command line, user, IP addresses, port, timestamp, and process identifiers.
7. Document analyst findings.
8. Stop the temporary Kali HTTP server.

## Step 1 — Start the Kali HTTP Server

From Kali:

```bash
python3 -m http.server 8000 --bind 192.168.64.3
```

Expected output should indicate that an HTTP server is listening on port `8000`.

Do not expose this service outside the isolated lab network.

## Step 2 — Generate the Windows Process and Connection

From Windows PowerShell, the planned request is:

```powershell
curl.exe http://192.168.64.3:8000/
```

This should create a `curl.exe` process and cause that process to initiate a TCP connection to Kali on destination port `8000`.

## Expected Telemetry

### Sysmon Event ID 1 — Process Create

Expected fields of interest:

- `Image` containing `curl.exe`
- `CommandLine` containing `http://192.168.64.3:8000/`
- `User`
- `ProcessId`
- `ProcessGuid`
- `ParentImage`
- timestamp

### Sysmon Event ID 3 — Network Connection

Expected fields of interest:

- `Image` containing `curl.exe`
- `Initiated: true`
- Windows source address
- Kali destination address `192.168.64.3`
- destination port `8000`
- `ProcessId`
- `ProcessGuid`
- timestamp

## Correlation Goal

The investigation should support a timeline similar to:

```text
Windows user launches curl.exe
        |
        | Sysmon Event ID 1
        v
curl.exe process created
        |
        | Sysmon Event ID 3
        v
TCP connection to 192.168.64.3:8000
        |
        v
Kali HTTP server receives request
```

The strongest correlation fields will be the matching process identity (`Image`, `ProcessId`, and especially `ProcessGuid` when available), the command line, timestamps, and network destination.

## Analyst Findings Template

- **What process executed:**
- **Command line:**
- **User:**
- **Parent process:**
- **Process ID / Process GUID:**
- **Network destination:**
- **Destination port:**
- **Sysmon Event IDs used:**
- **External confirmation:**
- **Conclusion:**

## Cleanup

Stop the temporary Kali HTTP server with:

```text
Ctrl+C
```

No permanent firewall rule should be required for this exercise because the connection is initiated outbound from Windows toward Kali.

## Memory Recall

1. What does Sysmon Event ID `1` record?
2. What does Sysmon Event ID `3` record?
3. Why is a process command line important during an investigation?
4. What does `Initiated: true` mean in a Sysmon network event?
5. Why is `ProcessGuid` useful when correlating multiple events?
6. What evidence would prove that `curl.exe` made the connection rather than another process?
7. Why is a timestamp alone not enough to correlate two events confidently?
8. What external evidence should appear on Kali when the HTTP request arrives?
