# Cybersecurity Home Lab Study Guide

This guide is maintained alongside the hands-on lab to reinforce understanding and memory recall.

## Core Concepts

### Windows Event ID 4624

Successful logon.

### Windows Event ID 4625

Failed logon.

### Sysmon Event ID 1

Process creation.

### Sysmon Event ID 3

Network connection telemetry.

### Windows Filtering Platform Event ID 5152

Windows Filtering Platform blocked a packet.

### Windows Filtering Platform Event ID 5157

Windows Filtering Platform blocked a connection.

### Ping

Uses ICMP to test basic IP reachability.

### IP Address

Identifies a network interface/host location for communication in the lab.

### Port

Identifies the application or service endpoint involved in TCP/UDP communication.

### TCP Listener

A process that waits on a specific TCP port for incoming connection attempts.

### TCP SYN

A SYN is the first control flag normally used when attempting to establish a TCP connection. In the firewall log, the `S` flag showed that the observed Nmap probes were SYN packets.

### Nmap `filtered`

`filtered` means Nmap could not determine whether a port was open or closed because the probe did not receive the normal response needed to make that distinction. Defender-side logs should be checked to understand what happened to the traffic.

### Ephemeral Source Port

A temporary client-side port chosen for an outbound connection. In the TCP 8080 exercise, Kali used source port `37760` while Windows listened on destination port `8080`.

### Sysmon `Initiated` Field

- `true` — the monitored process initiated the connection.
- `false` — the monitored process accepted a connection initiated elsewhere.

In the TCP 8080 exercise, Windows showed `Initiated: false` because Kali initiated the connection.

## Investigation Sequence

When reviewing a security event, ask:

1. When did it happen?
2. Which host generated the event?
3. Which user was involved?
4. Which process was involved?
5. What source and destination systems were involved?
6. What protocol and ports were used?
7. Did the action succeed, fail, or get blocked?
8. Which side initiated the connection?
9. Is there a repeated pattern across multiple ports or events?
10. What other telemetry sources correlate with it?
11. What conclusion does the combined evidence support?

## TCP 8080 Exercise — Verified Evidence

Known test activity:

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

### Why This Event Was the Match

The event matched the known activity across multiple fields:

- Correct protocol: TCP
- Correct source: Kali
- Correct destination: Windows
- Correct destination port: 8080
- Correct direction: inbound to Windows
- Correct receiving process: PowerShell
- Correct time window

Unrelated Event ID 3 entries were rejected when they showed different protocols, processes, directions, ports, or timestamps.

### Correlation Lesson

The connection was confirmed using three observations:

1. Kali Netcat reported port `8080` open.
2. Windows PowerShell displayed `Connection received!`.
3. Sysmon Event ID `3` recorded the matching network telemetry.

This is a basic example of event correlation.

## Port-Scan Detection Exercise — Verified Evidence

Kali generated a controlled SYN scan against the Windows lab endpoint:

```bash
sudo nmap -Pn -sS -p 21,22,23,80,443,445,3389,8080 192.168.64.2
```

All eight ports were reported by Nmap as `filtered`.

### Firewall Log Evidence

Windows Firewall blocked-packet logging was enabled on the active Public profile. The basic `pfirewall.log` visibly recorded dropped SYN probes from Kali to Windows port `445`.

One log line could be interpreted as:

```text
DROP TCP 192.168.64.3 192.168.64.2 <ephemeral-port> 445 ... S ...
```

- `DROP` — blocked by the firewall
- `TCP` — protocol
- `192.168.64.3` — Kali source
- `192.168.64.2` — Windows destination
- `445` — destination port
- `S` — SYN flag

The basic firewall log did not visibly show all eight ports, so we did not assume complete visibility.

### Windows Filtering Platform Evidence

Additional auditing was enabled for:

- `Filtering Platform Packet Drop`
- `Filtering Platform Connection`

After rerunning the same scan, Security events appeared at approximately `9:22:06–9:22:07 PM`.

A full Event ID `5152` example showed:

- Direction: `Inbound`
- Source Address: `192.168.64.3`
- Source Port: `59432`
- Destination Address: `192.168.64.2`
- Destination Port: `443`
- Protocol: `6` (TCP)

A PowerShell extraction of the WFP events confirmed Event ID `5152` for all eight scanned destination ports:

- `21`
- `22`
- `23`
- `80`
- `443`
- `445`
- `3389`
- `8080`

Each appeared in the packet-block events during the scan window. In this capture, port `445` also produced Event ID `5157` blocked-connection events.

### Detection Pattern

```text
192.168.64.3
      |
      +--> 21
      +--> 22
      +--> 23
      +--> 80
      +--> 443
      +--> 445
      +--> 3389
      +--> 8080

Multiple blocked TCP probes within ~1 second
      ↓
Consistent with controlled port-scanning / reconnaissance behavior
```

The conclusion did not come from one blocked packet. It came from the repeated pattern of one source probing multiple destination ports in a very short period and matching the known Nmap activity.

### Multi-Source Correlation Lesson

The scan was supported by:

1. Nmap output on Kali
2. Windows Firewall `DROP TCP` evidence
3. Security Event ID `5152` across all eight ports
4. Event ID `5157` for port 445 in this capture
5. Matching timestamps

One telemetry source may be incomplete. Analysts should correlate sources instead of assuming that a single log shows the entire event.

## Timestamp and Time Synchronization Lesson

During the investigation, the Windows VM appeared about three hours behind the host system. The root cause was an incorrect Windows time-zone setting: the VM was configured for Pacific Time while the lab was operating in Eastern Time.

The Windows time zone was corrected with:

```powershell
Set-TimeZone -Id "Eastern Standard Time"
```

Verification:

```powershell
Get-TimeZone
Get-Date
```

The Windows Time service was then checked:

```powershell
Get-Service W32Time
```

It was initially stopped. It was started with:

```powershell
Start-Service W32Time
```

Before synchronization, `w32tm /query /status` showed:

- `Leap Indicator: 3 (not synchronized)`
- `Last Successful Sync Time: unspecified`
- `Source: Local CMOS Clock`

A synchronization was requested with:

```powershell
w32tm /resync
```

After synchronization, verification showed:

- `Leap Indicator: 0 (no warning)`
- `Stratum: 5`
- `Last Successful Sync Time: 8/17/2026 7:38:41 PM`
- `Source: time.windows.com,0x9`

The source was independently confirmed with:

```powershell
w32tm /query /source
```

### Kali Time Verification

Kali was verified with:

```bash
timedatectl
```

The result showed:

- `Time zone: America/New_York (EDT, -0400)`
- `System clock synchronized: yes`
- `NTP service: active`
- `RTC in local TZ: no`

This confirmed that the Kali VM was already synchronized and using the correct Eastern time zone. With Windows corrected and synchronized, both systems can now be correlated using consistent timestamps.

### Analyst Lesson

If event timestamps appear wrong, do not immediately assume the log data is corrupt. Check:

1. System time zone
2. Current local time
3. Time synchronization service status
4. Configured time source
5. UTC versus local-time fields

Accurate and synchronized clocks are critical when correlating events across multiple systems.

## Commands to Recognize

Windows hostname:

```powershell
hostname
```

Windows addressing:

```powershell
ipconfig
```

Kali addressing:

```bash
ip addr
```

Basic reachability:

```bash
ping <IP>
```

TCP port test with Netcat:

```bash
nc -vz <IP> <PORT>
```

Controlled Nmap SYN scan:

```bash
sudo nmap -Pn -sS -p 21,22,23,80,443,445,3389,8080 192.168.64.2
```

Create the lab TCP 8080 firewall rule:

```powershell
New-NetFirewallRule -DisplayName "Lab TCP 8080 from Kali" -Direction Inbound -Protocol TCP -LocalPort 8080 -RemoteAddress 192.168.64.3 -Action Allow
```

Check Windows network profile:

```powershell
Get-NetConnectionProfile
```

Enable blocked-packet logging on the Public firewall profile:

```powershell
Set-NetFirewallProfile -Name Public -LogBlocked True
```

Check Windows time zone:

```powershell
Get-TimeZone
```

Check Windows Time status:

```powershell
w32tm /query /status
```

Check Windows time source:

```powershell
w32tm /query /source
```

Request Windows time synchronization:

```powershell
w32tm /resync
```

Check Kali time and NTP status:

```bash
timedatectl
```

## Memory Recall Questions

Try answering these without looking at the documentation.

1. What is the role of `LAB-ENDPOINT-01`?
2. What is the role of `LAB-KALI-01`?
3. What does Event ID `4624` mean?
4. What does Event ID `4625` mean?
5. What does Sysmon Event ID `1` mean?
6. What does Sysmon Event ID `3` mean?
7. What does WFP Event ID `5152` mean?
8. What does WFP Event ID `5157` mean?
9. What protocol does ping use?
10. Why does successful ping not prove TCP port `8080` is open?
11. Why should an analyst correlate multiple events?
12. Which fields would you inspect to explain a network connection?
13. Why can command-line data be important during process analysis?
14. Why are IP addresses re-verified before network exercises?
15. What does `nc -vz <IP> <PORT>` do?
16. Why should lab firewall rules be narrowly scoped?
17. What evidence proved that Kali communicated with Windows in the TCP 8080 exercise?
18. What did `Initiated: false` mean in the Sysmon event?
19. Why was Kali's source port `37760` different from Windows destination port `8080`?
20. How did we distinguish the correct Event ID 3 from unrelated background network events?
21. What process owned the Windows listener?
22. What does Nmap `-sS` do?
23. What does Nmap `-Pn` do?
24. What does `filtered` mean in Nmap output?
25. What did the `S` flag mean in the Windows Firewall log?
26. Which eight destination ports were used in the controlled scan?
27. Why did we enable WFP auditing after checking `pfirewall.log`?
28. What pattern made the WFP events consistent with port scanning?
29. Why should one isolated blocked packet not automatically be labeled a port scan?
30. What caused the Windows VM to appear three hours behind?
31. What did `Source: Local CMOS Clock` tell us before synchronization?
32. What command verifies the current Windows time source?
33. What showed that Windows successfully synchronized after the resync?
34. What does `System clock synchronized: yes` tell you on Kali?
35. Why should both systems be time-synchronized before correlating events?

## Recall Goal

The goal is to progress from:

**Recognition** — “I understand this when I see it.”

To:

**Recall** — “I can explain it without looking.”

To:

**Application** — “I can perform the procedure and interpret the results independently.”
