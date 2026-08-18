# Network Connectivity Validation

## Objective

Validate network communication between the monitored Windows endpoint and the Kali test system before performing traffic-based security investigations.

## Environment

- `LAB-ENDPOINT-01` — Windows 11 — `192.168.64.2`
- `LAB-KALI-01` — Kali Linux — `192.168.64.3`
- Virtual network — `192.168.64.0/24`

## Validation

Host addressing was verified with `ipconfig` on Windows and `ip addr` on Kali. ICMP connectivity was then tested in both directions.

```text
LAB-KALI-01  192.168.64.3
        ↕ ICMP
LAB-ENDPOINT-01  192.168.64.2
```

Successful ping confirmed basic IP reachability between the two VMs.

## Analyst Interpretation

ICMP reachability confirms that the systems can communicate at the IP layer, but it does **not** prove that a TCP or UDP application service is listening or reachable. Later investigations therefore used service-specific tests such as Netcat, HTTP, and Nmap in addition to ping.

Mapping IP addresses back to system roles also makes network telemetry immediately actionable:

```text
192.168.64.3 → 192.168.64.2
```

becomes:

```text
LAB-KALI-01 → LAB-ENDPOINT-01
```

## Findings

- Both systems were attached to the intended virtual network.
- Bidirectional IP reachability was established.
- The system-to-IP mapping was documented for later event correlation.
- The distinction between host reachability and application-port reachability was validated.

## Skills Demonstrated

- TCP/IP fundamentals
- Windows and Linux network inspection
- ICMP connectivity testing
- Host/IP role mapping
- Network troubleshooting methodology
