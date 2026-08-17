# Network Connectivity Verification

## Objective

Verify that the Kali Linux and Windows virtual machines can communicate before running security exercises that depend on network traffic.

## Current Lab Systems

- Windows endpoint: `LAB-ENDPOINT-01`
- Kali test system: `LAB-KALI-01`

Current observed IP addresses:

- Windows: `192.168.64.2`
- Kali: `192.168.64.3`

## Verify Windows Address

```powershell
ipconfig
```

## Verify Kali Address

```bash
ip addr
```

## Test Connectivity

From Kali:

```bash
ping 192.168.64.2
```

From Windows:

```powershell
ping 192.168.64.3
```

## What Ping Proves

Ping uses ICMP and verifies basic IP reachability between systems.

A successful ping does **not** prove that a particular TCP or UDP service is open. Service-specific connectivity must be tested separately.

## Analyst Interpretation

Before investigating network activity, identify which address belongs to which host. This makes traffic such as:

```text
192.168.64.3 -> 192.168.64.2
```

readable as:

```text
LAB-KALI-01 -> LAB-ENDPOINT-01
```

## Troubleshooting

If ping fails, check:

1. Both VMs are running.
2. Both systems have valid addresses.
3. Both VMs are attached to the intended UTM network.
4. Local firewall rules permit the traffic being tested.
5. The destination IP has not changed since the previous session.

## Memory Recall

1. What protocol does ping use?
2. What does a successful ping prove?
3. What does it *not* prove?
4. Why should you verify IP addresses at the beginning of a session?
5. Which system is the source when Kali pings Windows?
