# TCP 8080 Investigation

## Objective

Generate a controlled inbound TCP connection from Kali Linux to the monitored Windows endpoint and identify the matching network telemetry in Sysmon.

## Environment and Tools

- Source: `LAB-KALI-01` — `192.168.64.3`
- Destination: `LAB-ENDPOINT-01` — `192.168.64.2`
- Protocol: TCP
- Destination port: `8080`
- Tools: PowerShell TCP listener, Windows Firewall, Netcat, Sysmon

## Detection / Investigation

A narrowly scoped Windows Firewall rule permitted TCP/8080 only from the Kali lab IP. A temporary PowerShell TCP listener was started on Windows, and Kali generated the connection with:

```bash
nc -vz 192.168.64.2 8080
```

Kali reported the port as open, while the Windows listener displayed `Connection received!`.

The Sysmon Operational log was then filtered for Event ID `3` and unrelated background connections were rejected until protocol, addresses, port, direction, process, and timestamp matched the known activity.

## Evidence

The matching Sysmon Event ID `3` showed:

- `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- `User: LAB-ENDPOINT-01\User1`
- `Protocol: tcp`
- `Initiated: false`
- `SourceIp: 192.168.64.3`
- `SourcePort: 37760`
- `DestinationIp: 192.168.64.2`
- `DestinationPort: 8080`

Traffic flow:

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

`Initiated: false` confirmed that the monitored Windows process accepted a connection initiated by the remote Kali system.

## Correlated Finding

Three independent observations supported the same conclusion:

1. Netcat reported TCP/8080 open.
2. The Windows listener confirmed the connection was received.
3. Sysmon Event ID `3` captured the matching process, direction, addresses, protocol, and ports.

**Finding:** `LAB-KALI-01` initiated a controlled inbound TCP connection to `LAB-ENDPOINT-01` on TCP/8080, and the Windows endpoint successfully recorded the activity in Sysmon.

## Additional Analyst Insight

A timestamp discrepancy discovered during the exercise was traced to an incorrect Windows time zone. The Windows endpoint was corrected to Eastern Time and synchronized with `time.windows.com`; Kali was verified as synchronized with NTP. This reinforced the importance of normalized clocks when correlating multi-system evidence.

## Skills Demonstrated

- Windows Firewall rule configuration
- TCP listener creation
- Netcat connectivity testing
- Sysmon Event ID `3` analysis
- Source/destination and connection-direction interpretation
- Multi-source event correlation
- Timestamp validation and synchronization
