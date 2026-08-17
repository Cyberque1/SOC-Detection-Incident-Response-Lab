# Windows Event Log Analysis

## Objective

Practice reading Windows Security logs and interpreting successful and failed authentication events.

## Event ID 4624 — Successful Logon

Windows Security Event ID `4624` indicates that an account successfully logged on.

When reviewing the event, identify:

- Timestamp
- Account name
- Logon type
- Source system or network information when available
- Whether the authentication was expected

### Analyst Question

A successful login is not automatically benign. Determine whether it followed suspicious failed attempts or occurred from an unexpected source.

## Event ID 4625 — Failed Logon

Windows Security Event ID `4625` indicates that an account failed to log on.

Potential explanations include:

- Mistyped password
- Expired or incorrect credentials
- Misconfigured application or service
- Password guessing
- Brute-force activity

### Investigation Pattern

```text
Repeated 4625 events
        |
        v
Identify source/user/time pattern
        |
        v
Look for subsequent 4624
        |
        v
Determine whether access eventually succeeded
```

## Why Correlation Matters

A single failed login may be normal. Multiple failures followed by a successful login can tell a much different story. Analysts correlate events to reconstruct the sequence rather than making a decision from one record.

## Memory Recall

1. What does Event ID 4624 represent?
2. What does Event ID 4625 represent?
3. Why might repeated 4625 events deserve investigation?
4. Why should you search for a 4624 after a series of 4625 events?
5. What additional fields would help determine whether an authentication event is suspicious?
