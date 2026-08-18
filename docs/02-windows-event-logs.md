# Windows Authentication Event Analysis

## Objective

Analyze Windows Security authentication events and use event sequence, account, source, and timing context to distinguish normal activity from activity that warrants investigation.

## Telemetry Reviewed

### Event ID 4624 — Successful Logon

A `4624` event records a successful Windows logon. Fields of interest include:

- timestamp
- account name
- logon type
- source/network information when available
- target system

### Event ID 4625 — Failed Logon

A `4625` event records a failed Windows logon. Potential causes range from user error or stale credentials to password guessing and brute-force activity.

## Investigation Approach

The analysis focused on sequence and context rather than treating one event as a verdict:

```text
Repeated 4625 failures
        ↓
Identify user + source + timing pattern
        ↓
Search for a subsequent 4624
        ↓
Determine whether authentication eventually succeeded
```

A successful logon is not automatically benign, and a failed logon is not automatically malicious. The surrounding pattern determines investigative priority.

## Findings

- Event ID `4624` was identified and interpreted as successful authentication telemetry.
- Event ID `4625` was identified and interpreted as failed authentication telemetry.
- Authentication events were evaluated as part of a timeline rather than as isolated records.
- The exercise established the basis for investigating repeated failures followed by successful access.

## Skills Demonstrated

- Windows Security log analysis
- Authentication-event triage
- Event ID interpretation
- Timeline and sequence analysis
- Context-based security investigation
