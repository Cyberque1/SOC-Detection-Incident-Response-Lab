# Sysmon Endpoint Monitoring

## Objective

Use Sysmon to collect higher-fidelity Windows endpoint telemetry and support process, network, DNS, file, and persistence investigations locally and through the centralized Wazuh SIEM.

## Current Configuration

The active Sysmon configuration on `LAB-ENDPOINT-01` uses SHA-256 hashing and collects these event categories:

- `ProcessCreate`
- `NetworkConnect`
- `DnsQuery`
- `FileCreate`
- targeted `RegistryEvent` telemetry for the Windows `Run` persistence path

After Wazuh deployment, the Sysmon Operational channel was also forwarded to the SIEM for centralized search and correlation.

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

This supports process-to-network correlation and connection-direction analysis.

### Event ID 11 — File Create

Useful fields include:

- creating process
- `ProcessId`
- `ProcessGuid`
- `TargetFilename`
- user
- event timestamp

This enables direct correlation between a running process and a file artifact it created.

### Event ID 13 — Registry Value Set

Useful fields include:

- `EventType`
- process identity
- `ProcessId`
- `ProcessGuid`
- `TargetObject`
- `Details`
- user

Targeted collection of the Windows `Run` path supports investigation of startup-persistence activity without enabling broad registry noise.

### Event ID 22 — DNS Query

Useful fields include:

- `QueryName`
- `QueryResults`
- `QueryStatus`
- process identity
- `ProcessId`
- `ProcessGuid`
- user

This supports process-to-DNS correlation and can be combined with Event ID `3` to connect domain resolution to subsequent network activity.

## Investigation Method

```text
Identify event
      ↓
Extract process/user/time fields
      ↓
Inspect command line, DNS, network, file, or registry fields
      ↓
Correlate by PID / ProcessGuid / timestamp
      ↓
Validate with another telemetry source
      ↓
Document finding
```

## Analyst Perspective

Sysmon provides telemetry, not a verdict. A process, network connection, DNS query, file creation, or registry modification must be interpreted in context and correlated with other evidence before activity is labeled benign or suspicious.

The lab also demonstrated that some Sysmon events may contain incomplete metadata. When a field such as `Image` or `ProcessGuid` is unavailable, correlation can still be supported by multiple aligned fields such as PID, destination, DNS result, direction, and precise timestamps.

## Skills Demonstrated

- Sysmon deployment and configuration
- Endpoint telemetry analysis
- Parent-child process investigation
- PID and ProcessGuid correlation
- Network and DNS analysis
- File-artifact analysis
- Registry persistence monitoring
- SHA-256 process hashing
- Centralized Sysmon analysis in Wazuh
- Investigation of incomplete telemetry
