# TCP 8080 Investigation

## Objective

Generate a controlled TCP connection from the Kali Linux VM to the monitored Windows endpoint, verify the connection, and locate the related telemetry in Sysmon.

## Why This Matters

SOC analysts need to connect network activity with endpoint evidence. This exercise links source and destination IP addresses, TCP ports, firewall behavior, a listening service, and Sysmon network telemetry.

## Environment

- Source: `LAB-KALI-01`
- Source IP: `192.168.64.3`
- Destination: `LAB-ENDPOINT-01`
- Destination IP: `192.168.64.2`
- Protocol: TCP
- Destination port: `8080`

> Verify current VM addresses before running the exercise because DHCP-assigned addresses can change.

## Step 1 — Create a Narrow Windows Firewall Rule

Open PowerShell as Administrator on Windows:

```powershell
New-NetFirewallRule -DisplayName "Lab TCP 8080 from Kali" -Direction Inbound -Protocol TCP -LocalPort 8080 -RemoteAddress 192.168.64.3 -Action Allow
```

### What This Does

Allows inbound TCP traffic to local port `8080` only when it originates from the Kali VM's current lab IP.

## Step 2 — Start a TCP Listener on Windows

```powershell
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any,8080)
$listener.Start()
Write-Host "Listening on TCP 8080..."
$client = $listener.AcceptTcpClient()
Write-Host "Connection received!"
$client.Close()
$listener.Stop()
```

Expected output before the connection:

```text
Listening on TCP 8080...
```

The terminal will appear to pause because `AcceptTcpClient()` is waiting for a remote client.

## Step 3 — Connect from Kali

```bash
nc -vz 192.168.64.2 8080
```

### Netcat Command Breakdown

- `nc` — Netcat networking utility
- `-v` — verbose output
- `-z` — connection/port test without normal application data
- `192.168.64.2` — Windows destination address
- `8080` — destination TCP port

## Expected Result

Kali should report that the connection succeeded.

Windows should show:

```text
Connection received!
```

This verifies a TCP connection from Kali to the Windows endpoint on port `8080`.

## Step 4 — Investigate Sysmon

Open Event Viewer and navigate to the Sysmon Operational log.

Filter or locate relevant Sysmon Event ID `3` entries around the exercise timestamp.

Record:

- Timestamp
- Image/process
- Protocol
- Source IP
- Source port
- Destination IP
- Destination port
- User

## Analyst Findings Template

Complete this after the exercise:

- **What happened:**
- **Source system:**
- **Destination system:**
- **Protocol/port:**
- **Evidence found:**
- **Process involved:**
- **Conclusion:**

## Troubleshooting

If the connection fails:

1. Re-check both VM IP addresses.
2. Confirm the Windows listener is still running.
3. Confirm the Windows firewall rule exists and uses Kali's current IP.
4. Verify basic network connectivity.
5. Confirm the command targets the Windows IP rather than Kali's own IP.

## Memory Recall

1. What is a TCP listener?
2. Why was port `8080` chosen for the exercise?
3. Why was the firewall rule limited to Kali's IP?
4. What does `nc -vz` test?
5. What does Sysmon Event ID `3` record?
6. Which fields would prove which hosts communicated?
7. Why should you correlate the exercise timestamp with the Sysmon event?
