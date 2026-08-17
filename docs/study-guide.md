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

## Investigation Sequence

When reviewing a security event, ask:

1. When did it happen?
2. Which host generated the event?
3. Which user was involved?
4. Which process was involved?
5. What source and destination systems were involved?
6. What protocol and ports were used?
7. Did the action succeed or fail?
8. What other events correlate with it?
9. What conclusion does the combined evidence support?

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
15. What evidence would prove that Kali communicated with Windows?

## Recall Goal

The goal is to progress from:

**Recognition** — “I understand this when I see it.”

To:

**Recall** — “I can explain it without looking.”

To:

**Application** — “I can perform the procedure and interpret the results independently.”
