# Controlled Port-Scan Detection

## Objective

Generate a limited Nmap TCP SYN scan from Kali Linux and detect the reconnaissance pattern from the Windows defender perspective using firewall and Windows Filtering Platform telemetry.

## Environment and Tools

- Scanner: `LAB-KALI-01` — `192.168.64.3`
- Target: `LAB-ENDPOINT-01` — `192.168.64.2`
- Tools: Nmap, Windows Firewall logging, Windows Filtering Platform (WFP), PowerShell
- Ports: `21, 22, 23, 80, 443, 445, 3389, 8080`

## Detection / Investigation

Kali generated a controlled SYN scan:

```bash
sudo nmap -Pn -sS -p 21,22,23,80,443,445,3389,8080 192.168.64.2
```

Nmap reported all eight ports as `filtered`, indicating that it could not determine open versus closed because normal responses were not received.

Windows Firewall blocked-packet logging initially exposed only part of the activity in `pfirewall.log`, including dropped SYN traffic to TCP/445. Rather than assume the text log was complete, WFP auditing was enabled to obtain stronger defender-side evidence.

## Evidence

Windows Security Event ID `5152` recorded blocked inbound TCP packets from `192.168.64.3` to all eight intended destination ports:

```text
21   22   23   80   443   445   3389   8080
```

An example Event ID `5152` showed:

- Direction: `Inbound`
- Source Address: `192.168.64.3`
- Source Port: `59432`
- Destination Address: `192.168.64.2`
- Destination Port: `443`
- Protocol: `6` (TCP)

Event ID `5157` also appeared for blocked TCP/445 connection activity in this capture.

The Windows Firewall text log independently showed entries consistent with:

```text
DROP TCP 192.168.64.3 192.168.64.2 <ephemeral-port> 445 ... S ...
```

where `S` represented the TCP SYN flag.

## Detection Logic

The activity was identified as scan-like behavior because one source rapidly probed multiple destination ports within approximately one second:

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
      |
      v
Rapid one-to-many-port pattern
      ↓
Consistent with reconnaissance / port scanning
```

A single blocked packet would not be enough to support this conclusion. The finding depended on source consistency, multiple destination ports, protocol, timing, and repeated blocked probes.

## Correlated Finding

The scan was supported by three telemetry perspectives:

1. **Kali:** Nmap generated the known eight-port SYN scan.
2. **Windows Firewall:** blocked TCP/SYN traffic from Kali was recorded.
3. **Windows Security / WFP:** Event ID `5152` confirmed blocked probes to all eight target ports, with `5157` providing additional connection-block evidence for TCP/445.

**Finding:** `LAB-ENDPOINT-01` detected and blocked a rapid multi-port TCP SYN scan originating from `LAB-KALI-01`. WFP Event ID `5152` provided the strongest evidence of the complete reconnaissance pattern.

## Skills Demonstrated

- Nmap SYN scanning in an authorized environment
- Windows Firewall log analysis
- Windows Filtering Platform auditing
- Security Event IDs `5152` and `5157`
- Detection-pattern recognition
- Multi-source telemetry correlation
- Evidence-based conclusions without overclaiming incomplete logs
