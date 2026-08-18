# File Creation, Hashing, and Sysmon Correlation

## Objective

Correlate process creation with file creation using Sysmon, then calculate a SHA-256 fingerprint to distinguish file content identity from filename.

## Environment and Tools

- Endpoint: `LAB-ENDPOINT-01`
- User: `LAB-ENDPOINT-01\User1`
- Tools: PowerShell, Sysmon, `Get-FileHash`
- Telemetry: Sysmon Event IDs `1` and `11`

## Sysmon Configuration Improvement

The initial file-creation test produced no Event ID `11` records. Investigation of the active Sysmon configuration showed that only `ProcessCreate`, `NetworkConnect`, and `DnsQuery` were enabled.

The existing configuration was backed up, then `FileCreate` telemetry was added:

```xml
<FileCreate onmatch="exclude" />
```

After reloading the configuration, `sysmon -c` confirmed that `FileCreate` was active.

This was a telemetry-coverage issue rather than a failure of the file-creation activity itself.

## Detection / Investigation

A benign text file was created from normal PowerShell. Sysmon Event ID `11` captured:

- `UtcTime: 2026-08-18 16:21:03.894`
- `ProcessId: 9280`
- `ProcessGuid: {44acc921-8651-6a84-ad02-000000000e00}`
- `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- `TargetFilename: C:\Users\User1\Documents\CyberLab\Lab9\lab9-test.txt`
- `User: LAB-ENDPOINT-01\User1`

The matching Sysmon Event ID `1` showed:

- `ProcessId: 9280`
- the same `ProcessGuid`
- `Image: powershell.exe`
- `IntegrityLevel: Medium`
- `ParentImage: C:\Windows\explorer.exe`

The matching PID and ProcessGuid established that the same PowerShell process recorded in Event ID `1` created the file recorded in Event ID `11`.

## File Hash Evidence

The file's SHA-256 was calculated with `Get-FileHash`:

```text
CECEB3F22E79D072CB63FBF6ECCBE3587AA8E150925B97E7290B856710AFD3C1
```

The file was then renamed without changing its contents. Its SHA-256 remained exactly the same.

```text
lab9-test.txt
      ↓ rename only
renamed-lab9-file.txt
      ↓
SHA-256 unchanged
```

This demonstrates that a filename is a label, while SHA-256 fingerprints the file's content. A hash can help compare an exact artifact across systems even when filenames differ.

A hash alone does not determine whether a file is malicious.

## Correlation Analysis

```text
explorer.exe
      ↓
powershell.exe — PID 9280
ProcessGuid {44acc921-8651-6a84-ad02-000000000e00}
      ↓
Sysmon Event ID 11
creates lab9-test.txt
      ↓
SHA-256 fingerprint
      ↓
rename file
      ↓
same SHA-256
```

The `Hashes` field in Sysmon Event ID `1` refers to the **process executable** (`powershell.exe`), not the file it created. The test artifact's SHA-256 was calculated separately.

## Correlated Finding

**Finding:** A normal-user PowerShell process launched by `explorer.exe` created the test file. Sysmon Event IDs `1` and `11` were directly correlated with both PID and ProcessGuid, and SHA-256 analysis demonstrated that the exact file content remained unchanged after the filename changed.

## Skills Demonstrated

- Sysmon configuration review and telemetry-gap identification
- Sysmon Event ID `11` file-creation analysis
- Event ID `1` / Event ID `11` correlation
- PID and ProcessGuid analysis
- SHA-256 hashing
- File-artifact identification
- Distinguishing executable hashes from created-file hashes
- Defensive configuration change management
