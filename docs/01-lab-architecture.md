# Lab Architecture

## Objective

Document the current cybersecurity home lab architecture and define the role of each virtual machine.

## Host System

- Apple Silicon MacBook Air M4
- 16 GB RAM
- UTM virtualization platform

## Virtual Machines

### LAB-ENDPOINT-01

- Operating system: Windows 11 ARM64
- Role: Monitored endpoint / simulated corporate workstation
- Current observed lab IP: `192.168.64.2`
- Security telemetry: Windows Event Logs and Sysmon

Primary uses:

- Authentication-event analysis
- Process creation analysis
- Network connection analysis
- Windows Firewall practice
- Incident investigation

### LAB-KALI-01

- Operating system: Kali Linux ARM64
- Role: Controlled testing system
- Current observed lab IP: `192.168.64.3`

Primary uses:

- Generate authorized network traffic
- Test connectivity and exposed services
- Produce activity for detection and investigation exercises

## Analyst Workflow

```text
LAB-KALI-01
    |
    | controlled activity
    v
LAB-ENDPOINT-01
    |
    | Windows + Sysmon telemetry
    v
Event investigation
    |
    v
Analyst findings
```

## Why This Matters

SOC analysts rarely investigate a log entry in isolation. They need to understand the systems involved, their roles, network relationships, and which telemetry sources can prove what happened.

## Verification Commands

Windows hostname:

```powershell
hostname
```

Windows network configuration:

```powershell
ipconfig
```

Kali network configuration:

```bash
ip addr
```

## Memory Recall

1. Which machine is the monitored endpoint?
2. Which machine generates controlled testing activity?
3. Why should IP addresses be verified before a lab exercise?
4. What telemetry sources are currently available on the Windows endpoint?
