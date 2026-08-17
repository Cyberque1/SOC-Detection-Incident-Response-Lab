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

### Verified Result

The rule was created successfully and showed:

- `Enabled: True`
- `Direction: Inbound`
- `Action: Allow`
- `PrimaryStatus: OK`

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

Verified output before the connection:

```text
Listening on TCP 8080...
```

The terminal paused at `AcceptTcpClient()` because the Windows endpoint was waiting for a remote client.

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

### Verified Kali Result

Kali returned:

```text
192.168.64.2: inverse host lookup failed: Unknown host
(UNKNOWN) [192.168.64.2] 8080 (http-alt) open
```

The inverse-host-lookup warning did not prevent the connection. The important result was that TCP port `8080` was reported as open.

### Verified Windows Result

Windows returned:

```text
Connection received!
```

This confirmed that the PowerShell listener accepted the inbound TCP connection.

## Step 4 — Investigate Sysmon

In Event Viewer:

`Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`

The log was filtered for Sysmon Event ID `3`.

Several unrelated Event ID 3 entries were reviewed first. Background events were rejected when their protocol, process, direction, addresses, ports, or timestamps did not match the known test activity.

## Verified Sysmon Evidence

The matching Event ID `3` contained:

- **Image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **User:** `LAB-ENDPOINT-01\User1`
- **Protocol:** `tcp`
- **Initiated:** `false`
- **Source IP:** `192.168.64.3`
- **Source port:** `37760`
- **Destination IP:** `192.168.64.2`
- **Destination hostname:** `Lab-Endpoint-01.myfiosgateway.com`
- **Destination port:** `8080`
- **Event Viewer logged time:** approximately `8/17/2026 4:13:17 PM`
- **Sysmon UtcTime field observed:** `2026-08-18 02:13:16.280`

## Analyst Interpretation

The evidence shows that `LAB-KALI-01` at `192.168.64.3` initiated a TCP connection from ephemeral source port `37760` to `LAB-ENDPOINT-01` at `192.168.64.2` on destination port `8080`.

Sysmon associated the receiving connection with `powershell.exe`, which matches the PowerShell TCP listener created on the Windows endpoint.

The field:

```text
Initiated: false
```

is important because it indicates that the monitored Windows process did not initiate the connection. It accepted an inbound connection initiated by the remote Kali system.

### Connection Flow

```text
LAB-KALI-01
192.168.64.3:37760
        |
        | TCP
        v
192.168.64.2:8080
LAB-ENDPOINT-01
powershell.exe listener
```

## Correlated Evidence

Three independent observations support the same conclusion:

1. Kali reported TCP port `8080` as open.
2. Windows PowerShell displayed `Connection received!`.
3. Sysmon Event ID `3` recorded the source, destination, protocol, port, direction, and receiving process.

This is event correlation: multiple pieces of telemetry are combined to reconstruct what occurred rather than relying on one log entry by itself.

## Analyst Findings

- **What happened:** A controlled inbound TCP connection was generated from Kali to Windows.
- **Source system:** `LAB-KALI-01` / `192.168.64.3`
- **Source port:** `37760` (ephemeral client port)
- **Destination system:** `LAB-ENDPOINT-01` / `192.168.64.2`
- **Protocol/port:** TCP/8080
- **Evidence found:** Kali Netcat output, Windows listener output, and Sysmon Event ID `3`
- **Process involved:** `powershell.exe`
- **Connection direction:** Inbound to the Windows endpoint (`Initiated: false`)
- **Conclusion:** The known Kali-to-Windows TCP test was successfully generated, received, and identified in endpoint telemetry.

## Timestamp Note

A difference was observed between the Sysmon `UtcTime` field and the local Event Viewer `Logged` time. Time synchronization and timezone configuration should be verified before future timeline-heavy investigations. Analysts should normalize timestamps before correlating events from multiple systems.

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
6. Which fields proved which hosts communicated?
7. What did `Initiated: false` tell us?
8. Why was source port `37760` different from destination port `8080`?
9. Why did the inverse-host-lookup warning not mean the TCP test failed?
10. Why should an analyst reject unrelated Event ID 3 entries instead of assuming the first one is relevant?
11. What three pieces of evidence were correlated to prove the connection?
12. Why should timestamps be normalized during an investigation?
