# Lab Architecture

## Objective

Design a small Blue Team / SOC environment that separates a monitored Windows endpoint, a controlled Kali Linux testing system, and a centralized Wazuh SIEM so security activity can be generated, collected, correlated, and investigated across multiple telemetry sources.

## Environment

- **Host:** Apple Silicon MacBook Air M4, 16 GB RAM
- **Hypervisor:** UTM
- **Endpoint:** `LAB-ENDPOINT-01` — Windows 11 ARM64
- **SIEM server:** `LAB-WAZUH-01` — Ubuntu Server / Wazuh
- **Test system:** `LAB-KALI-01` — Kali Linux ARM64
- **Virtual network:** `192.168.64.0/24`

Current lab addressing:

| System | Role | IP |
|---|---|---|
| `LAB-ENDPOINT-01` | Monitored Windows endpoint | `192.168.64.2` |
| `LAB-KALI-01` | Controlled traffic/test system | `192.168.64.3` |
| `LAB-WAZUH-01` | Centralized Wazuh SIEM | `192.168.64.4` |

## Architecture

```text
                         MacBook Air M4
                              |
                             UTM
                              |
                     Virtual Lab Network
                   /           |           \
                  /            |            \
       LAB-ENDPOINT-01    LAB-WAZUH-01    LAB-KALI-01
         Windows 11        Ubuntu/Wazuh      Kali Linux
             |                  |                |
    Windows Event Logs     Wazuh Manager   Controlled tests
           Sysmon            Indexer       Nmap / Netcat
    PowerShell logging       Dashboard
    Microsoft Defender       Filebeat
             |                  |
             +-------> Centralized SIEM
                         Detection & Analysis
```

## Telemetry Sources

The Windows endpoint provides:

- Windows Security, Application, and System logs
- Sysmon process, network, DNS, file-creation, and targeted registry telemetry
- PowerShell Operational logs / Event ID `4104`
- Microsoft Defender Operational logs
- Windows Firewall logs
- Windows Filtering Platform Security events

The Wazuh server centralizes selected Windows event channels and makes both alerts and raw archived events searchable for investigation and threat hunting.

The Kali VM is used only to generate controlled activity such as connectivity tests, TCP connections, HTTP requests, and limited Nmap scans.

## Analyst Workflow

```text
Controlled activity
        ↓
Endpoint telemetry
        ↓
Wazuh collection and indexing
        ↓
Filtering, field extraction, and correlation
        ↓
Timeline / scope / containment analysis
        ↓
Analyst finding and documentation
```

## Skills Demonstrated

- Virtual lab and SIEM architecture
- Windows and Linux system administration
- Network-role mapping
- Defensive telemetry planning
- Centralized log collection design
- Separation of test-generation and monitored systems
- Cross-source security-event correlation
