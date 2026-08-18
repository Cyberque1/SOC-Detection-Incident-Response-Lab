# Cybersecurity Home Lab

A hands-on Blue Team / SOC portfolio demonstrating Windows endpoint monitoring, event-log analysis, Sysmon telemetry, PowerShell visibility, network detection, persistence analysis, and multi-source security-event correlation.

## Project Goal

Build and investigate realistic, controlled security activity using a monitored Windows endpoint and a Kali Linux test system.

The analyst workflow used throughout the project is:

**Generate activity → Collect telemetry → Investigate → Correlate evidence → Document findings**

All testing is performed in a personally controlled virtual lab.

## Lab Architecture

```text
                     MacBook Air M4
                          |
                         UTM
                          |
                 Virtual Lab Network
                    /             \
                   /               \
        LAB-ENDPOINT-01         LAB-KALI-01
          Windows 11              Kali Linux
              |                        |
     Windows Event Logs          Controlled tests
            Sysmon               Nmap / Netcat
     PowerShell logging
              |
              v
       Detection & Analysis
```

| System | Role | Lab IP |
|---|---|---|
| `LAB-ENDPOINT-01` | Monitored Windows 11 endpoint | `192.168.64.2` |
| `LAB-KALI-01` | Controlled traffic/test system | `192.168.64.3` |

## Portfolio Highlights

### Port-Scan Detection
Generated a controlled Nmap SYN scan and detected the activity from the Windows defender perspective using Windows Firewall logs and Windows Filtering Platform events. Correlated a rapid one-to-many-port probe pattern across TCP ports `21, 22, 23, 80, 443, 445, 3389, 8080`.

[View investigation](docs/06-port-scan-detection.md)

### Process-to-Network Correlation
Correlated Sysmon Event ID `1` and Event ID `3` to connect a `curl.exe` process to an outbound HTTP connection. Used PID, destination, direction, command line, precise UTC timestamps, and an independent Kali HTTP log to reconstruct the activity.

[View investigation](docs/07-process-network-correlation.md)

### PowerShell Script Block Analysis
Enabled PowerShell Script Block Logging and correlated Sysmon Event ID `1` with PowerShell Event ID `4104`. Demonstrated how Sysmon exposes `-EncodedCommand` while Event ID `4104` reveals the readable PowerShell code executed by the same process.

[View investigation](docs/08-powershell-script-block-logging.md)

### File Creation and Hash Analysis
Expanded the Sysmon configuration to collect Event ID `11`, correlated process creation with file creation using PID and ProcessGuid, calculated a SHA-256 fingerprint, and demonstrated that renaming a file does not change its content hash.

[View investigation](docs/09-file-creation-hashing.md)

### Registry Persistence Detection
Added targeted Sysmon registry monitoring for the Windows `Run` key, generated a benign startup entry, and correlated Sysmon Event ID `13` with Event ID `1` using PID and ProcessGuid to identify the process responsible for the persistence-related registry modification.

[View investigation](docs/10-registry-persistence-detection.md)

## Skills Demonstrated

- Windows Event Viewer and Security log analysis
- Sysmon configuration and telemetry analysis
- Windows Filtering Platform event analysis
- PowerShell Script Block Logging
- Windows registry and startup-persistence analysis
- Process and parent-child process analysis
- TCP/IP and port-level traffic analysis
- Nmap and Netcat in an authorized lab environment
- Windows Firewall logging and policy inspection
- Event correlation across multiple telemetry sources
- Timeline reconstruction using UTC and local timestamps
- SHA-256 hashing and file-artifact analysis
- PowerShell-based log querying and structured XML parsing
- Technical security documentation

## Investigations

| Document | Focus |
|---|---|
| [01 — Lab Architecture](docs/01-lab-architecture.md) | Virtual environment, roles, and telemetry sources |
| [02 — Windows Event Logs](docs/02-windows-event-logs.md) | Authentication-event analysis with 4624/4625 |
| [03 — Sysmon Monitoring](docs/03-sysmon-monitoring.md) | Endpoint process and network telemetry |
| [04 — Network Connectivity](docs/04-network-connectivity.md) | Network validation and host-role mapping |
| [05 — TCP 8080 Investigation](docs/05-tcp-8080-investigation.md) | Inbound TCP connection and Sysmon Event ID 3 |
| [06 — Port-Scan Detection](docs/06-port-scan-detection.md) | Nmap reconnaissance detection with WFP events |
| [07 — Process-to-Network Correlation](docs/07-process-network-correlation.md) | Sysmon Event IDs 1 + 3 and timeline reconstruction |
| [08 — PowerShell Script Block Logging](docs/08-powershell-script-block-logging.md) | Encoded PowerShell analysis with Event ID 4104 |
| [09 — File Creation and Hashing](docs/09-file-creation-hashing.md) | Sysmon Event ID 11, ProcessGuid, and SHA-256 |
| [10 — Registry Persistence Detection](docs/10-registry-persistence-detection.md) | Sysmon Event ID 13 and process-to-registry correlation |

## Security and Scope

All activity documented here is generated inside an isolated, personally controlled lab for defensive learning and detection engineering practice.

Virtual machine images, credentials, secrets, private keys, tokens, and other sensitive material are not stored in this repository.
