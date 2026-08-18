# Sysmon Endpoint Monitoring

## Objective

Use Sysmon to collect higher-fidelity Windows endpoint telemetry and support process, network, DNS, and file-based investigations.

## Current Configuration

The active Sysmon configuration on `LAB-ENDPOINT-01` uses SHA-256 hashing and collects these event categories:

- `ProcessCreate`
- `NetworkConnect`
- `DnsQuery`
- `FileCreate`

## Key Event IDs

### Event ID 1 — Process Create

Useful fields include:

- `Image`
- `CommandLine`
- `ParentImage`
- `User`
- `IntegrityLevel`
- `ProcessId`
- `ProcessGuid`
- executable hashes

This telemetry supports parent-child process analysis and helps distinguish a normal executable name from a suspicious invocation or command line.

### Event ID 3 — Network Connection

Useful fields include:

- process identity
- protocol
- `Initiated`
- source IP/port
- destination IP/port

This supports process-to-network correlation and direction analysis.

### Event ID 11 — File Create

Useful fields include:

- creating process
- `ProcessId`
- `ProcessGuid`
- `TargetFilename`
- user
- event timestamp

This enables direct correlation between a running process and a file artifact it created.

## Investigation Method

```text
Identify event
      ↓
Extract process/user/time fields
      ↓
Inspect command line or network/file fields
      ↓
Correlate by PID / ProcessGuid / timestamp
      ↓
Validate with another telemetry source
      ↓
Document finding
```

## Analyst Perspective

Sysmon provides telemetry, not a verdict. A process, network connection, or file creation must be interpreted in context and correlated with other evidence before activity is labeled benign or suspicious.

## Skills Demonstrated

- Sysmon deployment and configuration
- Endpoint telemetry analysis
- Parent-child process investigation
- PID and ProcessGuid correlation
- Network and file artifact analysis
- SHA-256 process hashing
