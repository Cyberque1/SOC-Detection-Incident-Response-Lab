# Lab Architecture

## Objective

Design a small Blue Team / SOC lab that separates a monitored Windows endpoint from a controlled Kali Linux testing system and provides multiple telemetry sources for investigation.

## Environment

- **Host:** Apple Silicon MacBook Air M4, 16 GB RAM
- **Hypervisor:** UTM
- **Endpoint:** `LAB-ENDPOINT-01` — Windows 11 ARM64
- **Test system:** `LAB-KALI-01` — Kali Linux ARM64
- **Virtual network:** `192.168.64.0/24`

Current lab addressing:

| System | Role | IP |
|---|---|---|
| `LAB-ENDPOINT-01` | Monitored endpoint | `192.168.64.2` |
| `LAB-KALI-01` | Controlled traffic generator | `192.168.64.3` |

## Architecture

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
      Windows Event Logs        Authorized testing
            Sysmon               Nmap / Netcat
      PowerShell logging
              |
              v
       Detection & Analysis
```

## Telemetry Sources

The Windows endpoint provides:

- Windows Security logs
- Sysmon process, network, DNS, and file-creation telemetry
- PowerShell Operational logs / Event ID `4104`
- Windows Firewall logs
- Windows Filtering Platform Security events

The Kali VM is used only to generate controlled activity such as connectivity tests, TCP connections, HTTP requests, and limited Nmap scans.

## Analyst Workflow

```text
Controlled activity
        ↓
Endpoint telemetry
        ↓
Log filtering and field extraction
        ↓
Cross-source event correlation
        ↓
Analyst finding
```

## Skills Demonstrated

- Virtual lab architecture
- Windows and Linux system administration
- Network-role mapping
- Defensive telemetry planning
- Separation of test-generation and monitored systems
- Security-event correlation design
