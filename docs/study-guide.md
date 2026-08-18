# Cybersecurity Home Lab Study Guide

This guide is maintained alongside the hands-on lab to reinforce understanding, memory recall, and analyst reasoning. Detailed procedures live in the numbered lab documents; this file focuses on the concepts and patterns you should remember.

## Core Event IDs

### Windows Security Event ID 4624

Successful logon.

### Windows Security Event ID 4625

Failed logon.

### Sysmon Event ID 1

Process creation. Useful fields include:

- `Image`
- `CommandLine`
- `User`
- `ProcessId`
- `ProcessGuid`
- `ParentImage`
- `ParentProcessId`
- hashes

### Sysmon Event ID 3

Network connection telemetry. Useful fields include:

- `Image`
- `ProcessId`
- `ProcessGuid`
- `Protocol`
- `Initiated`
- `SourceIp`
- `SourcePort`
- `DestinationIp`
- `DestinationPort`

### PowerShell Event ID 4104

PowerShell Script Block Logging. Useful for seeing the PowerShell code that actually executed, including readable script content associated with an encoded or dynamically constructed command.

### Windows Filtering Platform Event ID 5152

Windows Filtering Platform blocked a packet.

### Windows Filtering Platform Event ID 5157

Windows Filtering Platform blocked a connection.

## Networking Concepts

### Ping

Uses ICMP to test basic IP reachability. A successful ping does **not** prove that a particular TCP or UDP port is reachable.

### IP Address

Identifies a network interface/location used for communication.

### Port

Identifies a service/application endpoint for TCP or UDP communication.

### TCP Listener

A process waiting on a TCP port for incoming connections.

### TCP SYN

A SYN is the first control flag normally used when attempting to establish a TCP connection.

### Ephemeral Source Port

A temporary client-side port selected for an outbound connection. The server normally listens on a known destination port while the client uses a temporary source port.

### Nmap `filtered`

`filtered` means Nmap could not determine open versus closed because it did not receive the normal response needed to make that distinction. Defender-side telemetry is needed to understand what happened to the probe.

### Sysmon `Initiated`

- `true` — the monitored system/process initiated the connection.
- `false` — the monitored system/process accepted a connection initiated elsewhere.

## Analyst Investigation Sequence

When reviewing activity, ask:

1. When did it happen?
2. Which host generated the event?
3. Which user was involved?
4. Which process was involved?
5. What command line was used?
6. What parent process launched it?
7. What source and destination systems were involved?
8. What protocol and ports were used?
9. Did the action succeed, fail, or get blocked?
10. Which side initiated the connection?
11. Is there a repeated pattern across multiple events or ports?
12. What other telemetry sources correlate with it?
13. What conclusion does the combined evidence support?

---

# Lab 5 — TCP 8080 Connection Investigation

Known activity:

```text
LAB-KALI-01
192.168.64.3:37760
        |
        | TCP
        v
192.168.64.2:8080
LAB-ENDPOINT-01
powershell.exe
```

Matching Sysmon Event ID `3` showed:

- `Image: powershell.exe`
- `Protocol: tcp`
- `Initiated: false`
- `SourceIp: 192.168.64.3`
- `SourcePort: 37760`
- `DestinationIp: 192.168.64.2`
- `DestinationPort: 8080`

### Correlation Lesson

Three observations supported the same conclusion:

1. Kali Netcat reported port `8080` open.
2. Windows PowerShell displayed `Connection received!`.
3. Sysmon Event ID `3` recorded matching network telemetry.

The important skill was rejecting unrelated Event ID 3 entries until protocol, direction, addresses, port, process, and time all matched.

---

# Lab 6 — Controlled Port-Scan Detection

Kali ran:

```bash
sudo nmap -Pn -sS -p 21,22,23,80,443,445,3389,8080 192.168.64.2
```

All eight ports were reported as `filtered`.

## Firewall Log Evidence

Windows Firewall logging visibly recorded dropped SYN traffic from Kali, including TCP `445`:

```text
DROP TCP 192.168.64.3 192.168.64.2 <ephemeral-port> 445 ... S ...
```

- `DROP` — blocked
- `TCP` — protocol
- `192.168.64.3` — Kali source
- `192.168.64.2` — Windows destination
- `445` — destination port
- `S` — SYN flag

The text firewall log did not visibly show all eight probes, so we did not assume complete visibility.

## Windows Filtering Platform Evidence

After enabling WFP auditing and rerunning the scan, Security Event ID `5152` showed blocked inbound TCP packets for all eight scanned destination ports:

- `21`
- `22`
- `23`
- `80`
- `443`
- `445`
- `3389`
- `8080`

Port `445` also produced Event ID `5157` in this capture.

### Detection Pattern

```text
One source IP
      |
      +--> many destination ports
      |
      +--> within a very short time window
      v
Potential reconnaissance / port-scanning behavior
```

A single blocked packet is not enough to label activity as a scan. The conclusion came from source consistency, many destination ports, tight timing, protocol, and matching known Nmap activity.

### Multi-Source Lesson

One telemetry source may be incomplete. Correlate:

- scanner output
- firewall logs
- Windows Security events
- timestamps

instead of assuming one log tells the entire story.

---

# Lab 7 — Process-to-Network Correlation

The goal was to connect **what process ran** to **what network connection it made**.

## Known Activity

Kali ran a temporary server on:

```text
192.168.64.3:8080
```

Windows ran:

```powershell
curl.exe http://192.168.64.3:8080/
```

Kali confirmed:

```text
192.168.64.2 - - [17/Aug/2026 23:51:34] "GET / HTTP/1.1" 200 -
```

HTTP `200` confirmed that the request succeeded.

## Sysmon Event ID 1 — Process Creation

Verified fields:

- `UtcTime: 2026-08-18 03:51:34.790`
- `ProcessId: 10740`
- `ProcessGuid: {44acc921-d6c6-6a83-4003-000000000b00}`
- `Image: C:\Windows\System32\curl.exe`
- `CommandLine: curl.exe http://192.168.64.3:8080/`
- `User: LAB-ENDPOINT-01\User1`
- `IntegrityLevel: High`
- `ParentProcessId: 8476`
- `ParentImage: powershell.exe`

Interpretation:

```text
powershell.exe
      ↓
creates curl.exe (PID 10740)
      ↓
command line targets Kali:8080
```

## Sysmon Event ID 3 — Network Connection

Verified fields:

- `UtcTime: 2026-08-18 03:51:34.874`
- `ProcessId: 10740`
- `ProcessGuid: 00000000-0000-0000-0000-000000000000`
- `Image: <unknown process>`
- `Protocol: tcp`
- `Initiated: true`
- `SourceIp: 192.168.64.2`
- `SourcePort: 53957`
- `DestinationIp: 192.168.64.3`
- `DestinationPort: 8080`

## Correlation Result

The same PID `10740` appeared in both Event ID `1` and Event ID `3`.

The Sysmon payload times were only about **84 milliseconds apart**:

```text
Event 1: 03:51:34.790
Event 3: 03:51:34.874
```

The network event's `ProcessGuid` was zeroed and its image was unknown, so those fields could not be used for correlation in this capture. Instead, the correlation was supported by:

- same PID `10740`
- exact destination `192.168.64.3:8080`
- `Initiated: true`
- Event ID 1 command line targeting that destination
- ~84 ms payload-time separation
- Kali HTTP `200` evidence at the same second

### Key Analyst Lesson

Telemetry can be incomplete. Do not abandon the investigation because one expected field is missing. Correlate using multiple available fields and independent evidence.

## Event Payload Time vs. Display Time

In Lab 7, Event Viewer displayed the Event ID `3` record several seconds after Event ID `1`, but Sysmon's internal `UtcTime` showed the network activity occurred only ~84 ms after process creation.

For precise sequencing, distinguish:

- **activity timestamp inside the event payload**, and
- **record/display time in the event viewer**.

## Structured Event Parsing

A PowerShell XML query was used to extract fields directly from Sysmon records instead of relying only on rendered message text. Structured fields make correlation easier and reduce dependence on display formatting.

---

# Lab 8 — PowerShell Script Block Logging

The goal was to compare **process telemetry** with **PowerShell code telemetry**.

## Script Block Logging

The PowerShell Operational log was enabled, but the full Script Block Logging policy was initially not configured. The policy was enabled by setting:

```text
EnableScriptBlockLogging = 1
```

Afterward, Event ID `4104` reliably captured benign test script blocks.

## First Marker Correlation

A normal PowerShell session launched a child PowerShell process containing `LAB8-4104-TEST`.

Sysmon Event ID `1` showed:

- child PID `972`
- parent PID `8000`
- `powershell.exe`
- command line containing the marker
- `IntegrityLevel: Medium`

PowerShell Event ID `4104` showed:

- `ProcessID: 972`
- readable script block containing `LAB8-4104-TEST`

The same PID directly correlated process creation to executed PowerShell code.

## Encoded Command Correlation

A harmless Base64-encoded PowerShell command was launched with `-EncodedCommand`.

Sysmon Event ID `1` showed:

- child PID `3724`
- parent PID `9320`
- `powershell.exe`
- `-EncodedCommand` plus Base64 data
- `IntegrityLevel: Medium`

PowerShell Event ID `4104` for the same PID `3724` revealed the readable code:

```powershell
$encodedMarker="LAB8-ENCODED-TEST"; Write-Output $encodedMarker
```

### Key Analyst Lesson

```text
Sysmon Event ID 1
        ↓
process + command line + parent + user + integrity

PowerShell Event ID 4104
        ↓
PowerShell code that actually executed
```

For encoded PowerShell, Sysmon can show that `-EncodedCommand` was used while 4104 can expose the readable script content.

Base64 is **encoding, not encryption**, and encoded PowerShell is **not automatically malicious**. It is a reason to investigate context such as the decoded code, parent process, user, integrity level, network behavior, persistence, and follow-on activity.

### Permissions Lesson

The normal PowerShell session could query the PowerShell Operational log but could not read the protected Sysmon Operational log. Sysmon investigation therefore required Administrator PowerShell, while the generated test activity remained non-elevated.

### Integrity Lesson

`IntegrityLevel: Medium` confirmed the Lab 8 child PowerShell processes ran as normal user processes. Earlier Lab 7 activity had shown `High` integrity because PowerShell had unintentionally been opening elevated before UAC was corrected.

---

# Time Synchronization Lesson

The Windows VM initially appeared three hours behind because it was configured for Pacific Time while the lab was operating in Eastern Time.

Corrected with:

```powershell
Set-TimeZone -Id "Eastern Standard Time"
```

Windows time synchronization was verified with:

```powershell
Get-Service W32Time
Start-Service W32Time
w32tm /resync
w32tm /query /status
w32tm /query /source
```

Successful state included:

- `Leap Indicator: 0 (no warning)`
- a successful synchronization time
- `Source: time.windows.com,0x9`

Kali was verified with:

```bash
timedatectl
```

and showed:

- `America/New_York`
- system clock synchronized
- NTP active

### Analyst Lesson

If timestamps look wrong, verify:

1. time zone
2. current local time
3. synchronization status
4. time source
5. UTC versus local time
6. payload timestamp versus event record/display timestamp

---

# Commands to Recognize

Windows hostname:

```powershell
hostname
```

Windows network configuration:

```powershell
ipconfig
```

Kali network configuration:

```bash
ip addr
```

Basic reachability:

```bash
ping <IP>
```

TCP port test:

```bash
nc -vz <IP> <PORT>
```

Controlled SYN scan:

```bash
sudo nmap -Pn -sS -p 21,22,23,80,443,445,3389,8080 192.168.64.2
```

Check Kali listening TCP sockets:

```bash
ss -ltn
```

Filter for one listener:

```bash
ss -ltn | grep ':8080'
```

Start a temporary Python HTTP server:

```bash
python3 -m http.server 8080 --bind 192.168.64.3
```

Generate a Windows HTTP request:

```powershell
curl.exe http://192.168.64.3:8080/
```

Check Windows network profile:

```powershell
Get-NetConnectionProfile
```

Check Windows time zone:

```powershell
Get-TimeZone
```

Check Windows time source/status:

```powershell
w32tm /query /status
w32tm /query /source
```

Check Kali time synchronization:

```bash
timedatectl
```

---

# Memory Recall Questions

Try answering without looking at the notes.

1. What does Windows Event ID `4624` mean?
2. What does Windows Event ID `4625` mean?
3. What does Sysmon Event ID `1` record?
4. What does Sysmon Event ID `3` record?
5. What does PowerShell Event ID `4104` record?
6. What does WFP Event ID `5152` mean?
7. What does WFP Event ID `5157` mean?
8. What protocol does ping use?
9. Why does successful ping not prove a TCP port is reachable?
10. What does `Initiated: true` mean?
11. What does `Initiated: false` mean?
12. What is an ephemeral source port?
13. What does Nmap `-sS` do?
14. What does Nmap `-Pn` do?
15. What does `filtered` mean in Nmap output?
16. What did the `S` flag mean in the firewall log?
17. Why was `pfirewall.log` alone insufficient to prove all eight scan probes were logged?
18. What pattern made the WFP records consistent with port scanning?
19. Why should one isolated blocked packet not automatically be labeled a scan?
20. In Lab 7, what process launched `curl.exe`?
21. What was the `curl.exe` PID?
22. What did its command line reveal?
23. What destination did `curl.exe` contact?
24. What did HTTP status `200` prove?
25. Why could the Event ID 3 `ProcessGuid` not be used in Lab 7?
26. Which other fields allowed the two Sysmon events to be correlated anyway?
27. Approximately how far apart were Event ID 1 and Event ID 3 using Sysmon `UtcTime`?
28. Why can payload time be more useful than Event Viewer display time?
29. Why are structured XML event fields useful during an investigation?
30. What command verifies that Kali is actually listening on TCP `8080`?
31. What troubleshooting sequence should you use when ping works but an application connection fails?
32. Why should analysts correlate multiple telemetry sources?
33. What caused the Windows VM to appear three hours behind earlier in the lab?
34. Why must clocks be synchronized before building multi-system timelines?
35. In Lab 8, what PID correlated the first script-block test across Sysmon and Event ID 4104?
36. What PID correlated the encoded-command test across Sysmon and Event ID 4104?
37. What did `IntegrityLevel: Medium` tell us about the Lab 8 PowerShell processes?
38. Why is `-EncodedCommand` a useful detection signal but not proof of malicious activity?
39. Why is Base64 encoding not the same as encryption?
40. Which event source exposed the readable contents of the encoded PowerShell command?
41. Why did the normal PowerShell session need an elevated analyst session to read Sysmon telemetry?

## Recall Goal

Progress from:

**Recognition** — “I understand it when I see it.”

To:

**Recall** — “I can explain it without looking.”

To:

**Application** — “I can perform the procedure and interpret the evidence independently.”
