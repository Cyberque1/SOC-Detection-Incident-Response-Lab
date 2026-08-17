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

### Ping

Uses ICMP to test basic IP reachability.

### IP Address

Identifies a network interface/host location for communication in the lab.

### Port

Identifies the application or service endpoint involved in TCP/UDP communication.

### TCP Listener

A process that waits on a specific TCP port for incoming connection attempts.

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
7. Did the action succeed or fail?
8. Which side initiated the connection?
9. What other events correlate with it?
10. What conclusion does the combined evidence support?

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

### Timestamp Lesson

The lab showed a discrepancy between Sysmon's `UtcTime` field and the local Event Viewer `Logged` time. Future investigations should verify time synchronization and normalize timestamps before building a timeline.

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

Create the lab TCP 8080 firewall rule:

```powershell
New-NetFirewallRule -DisplayName "Lab TCP 8080 from Kali" -Direction Inbound -Protocol TCP -LocalPort 8080 -RemoteAddress 192.168.64.3 -Action Allow
```

## Memory Recall Questions

Try answering these without looking at the documentation.

1. What is the role of `LAB-ENDPOINT-01`?
2. What is the role of `LAB-KALI-01`?
3. What does Event ID `4624` mean?
4. What does Event ID `4625` mean?
5. What does Sysmon Event ID `1` mean?
6. What does Sysmon Event ID `3` mean?
7. What protocol does ping use?
8. Why does successful ping not prove TCP port `8080` is open?
9. Why should an analyst correlate multiple events?
10. Which fields would you inspect to explain a network connection?
11. Why can command-line data be important during process analysis?
12. Why are IP addresses re-verified before network exercises?
13. What does `nc -vz <IP> <PORT>` do?
14. Why should lab firewall rules be narrowly scoped?
15. What evidence proved that Kali communicated with Windows?
16. What did `Initiated: false` mean in our Sysmon event?
17. Why was Kali's source port `37760` different from Windows destination port `8080`?
18. How did we distinguish the correct Event ID 3 from unrelated background network events?
19. What process owned the Windows listener?
20. Why is timestamp normalization important during an investigation?

## Recall Goal

The goal is to progress from:

**Recognition** — “I understand this when I see it.”

To:

**Recall** — “I can explain it without looking.”

To:

**Application** — “I can perform the procedure and interpret the results independently.”
