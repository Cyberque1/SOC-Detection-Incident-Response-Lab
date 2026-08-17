# Cybersecurity Home Lab

A hands-on Blue Team / SOC cybersecurity home lab built to practice endpoint monitoring, Windows event analysis, Sysmon telemetry, TCP/IP networking, controlled adversary simulation, and incident investigation.

> **Status:** Active build. This repository is being documented alongside the hands-on lab so each exercise produces both technical evidence and a repeatable study procedure.

## Lab Goal

The lab follows a simple analyst workflow:

**Generate activity → Collect telemetry → Investigate logs → Correlate events → Document findings**

Kali Linux is used as a controlled testing system to generate authorized activity against a monitored Windows endpoint. The Windows system is used to collect and analyze endpoint and security telemetry.

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
            Sysmon              Test / Traffic
              |
       Windows Event Logs
```

### Current Systems

| System | Role | Current observed IP* |
|---|---|---|
| `LAB-ENDPOINT-01` | Monitored Windows endpoint | `192.168.64.2` |
| `LAB-KALI-01` | Controlled test system | `192.168.64.3` |

\*Virtual-machine addresses can change. IPs are verified before exercises that depend on them.

## Work Completed to Date

- Built a Windows 11 ARM64 endpoint in UTM
- Built a Kali Linux ARM64 test VM
- Configured the Windows endpoint hostname
- Installed and configured Sysmon
- Practiced Windows Security log analysis
- Investigated Event ID `4624` — successful logon
- Investigated Event ID `4625` — failed logon
- Investigated Sysmon Event ID `1` — process creation
- Introduced Sysmon Event ID `3` — network connection
- Verified network connectivity between Kali and Windows
- Began controlled Kali-to-Windows TCP testing

## Skills Demonstrated

- Windows Event Viewer
- Windows Security event analysis
- Sysmon telemetry analysis
- TCP/IP fundamentals
- Windows Firewall configuration
- Process investigation
- Network connection investigation
- Security event correlation
- Controlled lab testing
- Technical documentation

## Repository Structure

```text
cybersecurity-home-lab/
├── README.md
├── docs/
│   ├── 01-lab-architecture.md
│   ├── 02-windows-event-logs.md
│   ├── 03-sysmon-monitoring.md
│   ├── 04-network-connectivity.md
│   ├── 05-tcp-8080-investigation.md
│   └── study-guide.md
├── screenshots/
├── scripts/
├── configs/
└── reports/
```

## Documentation Approach

Each lab exercise is documented with:

1. **Objective** — what the exercise is designed to teach
2. **Why it matters** — how the skill applies to SOC / Blue Team work
3. **Procedure** — commands and configuration steps
4. **Expected result** — what successful execution should look like
5. **Verification** — evidence that the activity occurred
6. **Analyst interpretation** — what the telemetry means
7. **Troubleshooting** — common problems and fixes
8. **Memory recall** — questions used to reinforce retention

## Current Exercise

The current lab exercise is generating a controlled TCP connection from Kali Linux to the Windows endpoint on TCP port `8080`, then locating and interpreting the corresponding telemetry in Sysmon.

See [`docs/05-tcp-8080-investigation.md`](docs/05-tcp-8080-investigation.md).

## Safety and Scope

All testing documented in this repository is performed in an isolated, personally controlled lab environment. Techniques are used for defensive learning, telemetry generation, and authorized security testing.

Virtual machine images, credentials, secrets, private keys, tokens, and other sensitive files are not stored in this repository.
