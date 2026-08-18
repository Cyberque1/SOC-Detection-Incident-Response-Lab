# Controlled Port-Scan Detection

## Objective

Generate a small, controlled TCP SYN scan from `LAB-KALI-01` against `LAB-ENDPOINT-01`, then identify the scan from the Windows defender perspective using Windows Firewall logging and Windows Filtering Platform (WFP) Security events.

## Why This Matters

Port scanning is commonly used during reconnaissance to identify exposed services. A SOC analyst should be able to distinguish ordinary network activity from a rapid pattern of probes across multiple destination ports and support the conclusion with log evidence.

## Lab Scope

This exercise was performed only against the personally controlled lab endpoint.

- Scanner: `LAB-KALI-01`
- Kali IP: `192.168.64.3`
- Target: `LAB-ENDPOINT-01`
- Windows IP: `192.168.64.2`
- Network: `192.168.64.0/24`

## Step 1 — Verify Current Addresses

Windows:

```powershell
ipconfig
```

Verified IPv4 address: `192.168.64.2`

Kali:

```bash
ip addr
```

Verified IPv4 address: `192.168.64.3/24`

## Step 2 — Identify the Active Windows Firewall Profile

```powershell
Get-NetConnectionProfile
```

Verified result:

- Interface: `Ethernet`
- Network category: `Public`

## Step 3 — Enable Blocked-Packet Logging

```powershell
Set-NetFirewallProfile -Name Public -LogBlocked True
```

Verification:

```powershell
Get-NetFirewallProfile -Name Public | Select-Object Name, Enabled, LogBlocked, LogFileName
```

Verified values:

- `Name: Public`
- `Enabled: True`
- `LogBlocked: True`
- `LogFileName: %systemroot%\system32\LogFiles\Firewall\pfirewall.log`

The log was confirmed readable with:

```powershell
Get-Content "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -Tail 20
```

## Step 4 — Generate the Controlled SYN Scan

From Kali:

```bash
sudo nmap -Pn -sS -p 21,22,23,80,443,445,3389,8080 192.168.64.2
```

### Command Breakdown

- `sudo` — permits raw-packet operations used by the SYN scan
- `nmap` — network scanning tool
- `-Pn` — skip host discovery and treat the target as online
- `-sS` — TCP SYN scan
- `-p` — scan only the listed destination ports

### Verified Nmap Result

All eight selected ports were reported as `filtered`:

- `21/tcp` — FTP
- `22/tcp` — SSH
- `23/tcp` — Telnet
- `80/tcp` — HTTP
- `443/tcp` — HTTPS
- `445/tcp` — Microsoft-DS / SMB
- `3389/tcp` — RDP
- `8080/tcp` — alternate HTTP / proxy

`filtered` indicated that Nmap could not determine open versus closed because the probes were not receiving normal responses.

## Step 5 — Review the Basic Firewall Log

The Windows Firewall log was searched for Kali's source IP:

```powershell
Get-Content "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" |
Where-Object { $_ -match "DROP TCP 192\.168\.64\.3 192\.168\.64\.2" } |
Select-Object -Last 50
```

The basic firewall log visibly recorded two dropped TCP SYN probes to destination port `445`:

```text
DROP TCP 192.168.64.3 192.168.64.2 <ephemeral-port> 445 ... S ...
```

### Analyst Interpretation

- `DROP` — firewall blocked the packet
- `TCP` — transport protocol
- `192.168.64.3` — Kali source
- `192.168.64.2` — Windows destination
- source port — temporary client-side port
- destination port `445` — SMB probe
- `S` — TCP SYN flag

The basic firewall log did not provide enough evidence in this capture to prove all eight scanned ports were logged, so a second telemetry source was enabled rather than assuming complete visibility.

## Step 6 — Enable Windows Filtering Platform Auditing

```powershell
auditpol /set /category:"System" /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
```

```powershell
auditpol /set /category:"System" /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

Verification showed `Success and Failure` for both audit subcategories.

## Step 7 — Rerun the Same Nmap Scan

After WFP auditing was enabled, the exact same eight-port SYN scan was run again from Kali.

## Step 8 — Query WFP Security Events

Windows Security events `5152` and `5157` were queried for recent events involving Kali:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=5152,5157
    StartTime=(Get-Date).AddMinutes(-5)
} | Where-Object {
    $_.Message -match '192\.168\.64\.3'
} | Select-Object TimeCreated, Id, Message
```

A burst of WFP events appeared at approximately `9:22:06–9:22:07 PM`, matching the scan window.

### Example Event 5152

One full event showed:

- Direction: `Inbound`
- Source Address: `192.168.64.3`
- Source Port: `59432`
- Destination Address: `192.168.64.2`
- Destination Port: `443`
- Protocol: `6` (TCP)

This directly tied a Kali TCP probe to the Windows endpoint on HTTPS port 443.

## Step 9 — Extract the Destination Ports

A PowerShell query extracted destination ports from the WFP event messages.

Verified WFP evidence showed Event ID `5152` for all eight intended destination ports:

- `21`
- `22`
- `23`
- `80`
- `443`
- `445`
- `3389`
- `8080`

In this capture, each of those ports appeared in `5152` packet-block events around the scan time. Port `445` also produced Event ID `5157` blocked-connection events.

## Event Meanings Used in This Exercise

### Event ID 5152

Windows Filtering Platform blocked a packet.

### Event ID 5157

Windows Filtering Platform blocked a connection.

For this specific capture, `5152` provided the clearest evidence of the multi-port probe pattern because all eight destination ports appeared there.

## Correlated Evidence

The scan was supported by multiple telemetry sources:

1. Kali Nmap showed all eight ports as `filtered`.
2. `pfirewall.log` recorded blocked SYN traffic from Kali, including port `445`.
3. Windows Security Event `5152` recorded blocked inbound TCP packets from `192.168.64.3` to all eight selected destination ports.
4. Windows Security Event `5157` also appeared for blocked port-445 connection activity in this capture.
5. Timestamps aligned within the known scan window.

## Analyst Findings

- **Observed activity:** Rapid inbound TCP probes against multiple Windows destination ports.
- **Source:** `LAB-KALI-01` / `192.168.64.3`
- **Destination:** `LAB-ENDPOINT-01` / `192.168.64.2`
- **Technique used in the lab:** Nmap TCP SYN scan
- **Ports tested:** `21, 22, 23, 80, 443, 445, 3389, 8080`
- **Primary defender evidence:** Windows Filtering Platform Event ID `5152`
- **Additional evidence:** Event ID `5157` for port 445 and Windows Firewall `DROP TCP` entries
- **Conclusion:** The Windows endpoint successfully logged and blocked the controlled multi-port SYN scan. The strongest indicator of scan behavior was a burst of blocked inbound TCP packets from one source IP to multiple destination ports within approximately one second.

## Detection Pattern

A useful analyst pattern from this exercise is:

```text
One source IP
      |
      +--> TCP/21
      +--> TCP/22
      +--> TCP/23
      +--> TCP/80
      +--> TCP/443
      +--> TCP/445
      +--> TCP/3389
      +--> TCP/8080

All within a very short time window
      ↓
Potential port-scanning / reconnaissance behavior
```

A single blocked packet is not enough to conclude scanning. The conclusion comes from the combination of source consistency, multiple destination ports, timing, protocol, and repeated blocked probes.

## Step 10 — Cleanup and Verification

The temporary auditing and firewall logging used for this exercise were disabled after the investigation.

```powershell
auditpol /set /category:"System" /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable
```

```powershell
auditpol /set /category:"System" /subcategory:"Filtering Platform Connection" /success:disable /failure:disable
```

```powershell
Set-NetFirewallProfile -Name Public -LogBlocked False
```

Verification commands:

```powershell
auditpol /get /subcategory:"Filtering Platform Packet Drop"
```

```powershell
auditpol /get /subcategory:"Filtering Platform Connection"
```

```powershell
Get-NetFirewallProfile -Name Public | Select-Object Name, Enabled, LogBlocked
```

Verified cleanup state:

- `Filtering Platform Packet Drop: No Auditing`
- `Filtering Platform Connection: No Auditing`
- Windows Firewall Public profile: `Enabled = True`
- Blocked-packet logging: `LogBlocked = False`

This confirms that the temporary telemetry settings were removed while Windows Firewall itself remained enabled.

## Key Lessons

1. Nmap's `filtered` result should be interpreted together with defender telemetry.
2. One log source may provide incomplete visibility.
3. Windows Firewall text logs and WFP Security events provide different levels of detail.
4. Event correlation is stronger than relying on one record.
5. A rapid one-to-many-port pattern from the same source can indicate reconnaissance.
6. Analysts should verify the exact ports and timestamps instead of assuming that every generated probe was logged.
7. Temporary audit and logging changes should be reverted and verified after the exercise.

## Memory Recall

1. What does `-sS` mean in Nmap?
2. What does `-Pn` do?
3. What does Nmap mean by `filtered`?
4. What does `DROP` mean in `pfirewall.log`?
5. What does an `S` TCP flag represent?
6. What does Event ID `5152` indicate?
7. What does Event ID `5157` indicate?
8. Which system was the source of the scan?
9. Which eight ports were scanned?
10. Why was the first firewall-log result not enough to claim all eight probes were recorded?
11. What additional sensor was enabled to improve visibility?
12. What pattern made the WFP events consistent with port scanning?
13. Why are source IP, destination ports, and timing more useful together than separately?
14. Why can a temporary source port change between probes?
15. Why should an analyst avoid labeling one isolated blocked packet as a port scan?
16. Why did we disable WFP auditing and blocked-packet logging after the exercise?
17. What verification proved that Windows Firewall itself remained enabled after cleanup?
