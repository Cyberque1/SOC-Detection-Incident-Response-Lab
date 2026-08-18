# Lab 9 — File Creation, Hashing, and Sysmon Correlation

## Objective

Create a benign file on `LAB-ENDPOINT-01`, enable and verify Sysmon File Create telemetry, correlate Sysmon Event ID `1` with Event ID `11`, calculate a SHA-256 hash for the created file, and demonstrate that renaming a file does not change its content hash.

## Why This Matters

SOC analysts often need to answer three different questions:

1. **What process ran?**
2. **What file did that process create?**
3. **What exact file contents were present?**

Sysmon Event ID `1` provides process-creation context, Sysmon Event ID `11` records file creation, and SHA-256 provides a content fingerprint that can be compared across systems or against threat-intelligence data.

## Lab Scope

This exercise was performed only inside the personally controlled Windows lab endpoint.

- Host: `LAB-ENDPOINT-01`
- User: `LAB-ENDPOINT-01\User1`
- Test directory: `C:\Users\User1\Documents\CyberLab\Lab9`
- Original filename: `lab9-test.txt`
- Renamed filename: `renamed-lab9-file.txt`

## Step 1 — Create a Dedicated Test Directory

From normal PowerShell:

```powershell
New-Item -ItemType Directory -Path "$env:USERPROFILE\Documents\CyberLab\Lab9" -Force
```

The directory was created successfully under:

```text
C:\Users\User1\Documents\CyberLab\Lab9
```

## Step 2 — Create the Test File

The file was created with:

```powershell
"Cybersecurity Lab 9 file creation test" |
Set-Content "$env:USERPROFILE\Documents\CyberLab\Lab9\lab9-test.txt"
```

Verification with `Get-Item` showed the file existed and was `40` bytes.

## Step 3 — Initial Sysmon Event ID 11 Check

A search for recent Sysmon Event ID `11` records returned no events.

A broader search for any Event ID `11` records also returned none.

This established that the file itself had been created correctly, but Sysmon was not currently collecting File Create telemetry.

### Analyst Lesson

The existence of a security tool does not guarantee that every event type is enabled. Telemetry coverage depends on configuration.

## Step 4 — Inspect the Active Sysmon Configuration

The active configuration was checked with:

```powershell
sysmon -c
```

The active config file was:

```text
C:\Sysmon\sysmonconfig.xml
```

The configured event rules were initially:

```text
ProcessCreate
NetworkConnect
DnsQuery
```

There was no `FileCreate` rule.

The XML itself confirmed the same result:

```powershell
Select-String -Path 'C:\Sysmon\sysmonconfig.xml' -Pattern '<FileCreate'
```

No output was returned.

## Step 5 — Back Up the Sysmon Configuration

Before changing telemetry collection, the existing configuration was backed up:

```powershell
Copy-Item 'C:\Sysmon\sysmonconfig.xml' 'C:\Sysmon\sysmonconfig-backup.xml'
```

The backup was verified with:

```powershell
Get-Item 'C:\Sysmon\sysmonconfig-backup.xml'
```

## Step 6 — Enable File Create Telemetry

The Sysmon configuration was updated to include:

```xml
<FileCreate onmatch="exclude" />
```

The resulting configuration was:

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="exclude" />
    <NetworkConnect onmatch="exclude" />
    <DnsQuery onmatch="exclude" />
    <FileCreate onmatch="exclude" />
  </EventFiltering>
</Sysmon>
```

The configuration was applied with:

```powershell
sysmon -c C:\Sysmon\sysmonconfig.xml
```

Sysmon returned:

```text
Configuration file validated.
Configuration updated.
```

A subsequent `sysmon -c` showed:

```text
ProcessCreate
NetworkConnect
FileCreate
DnsQuery
```

confirming File Create telemetry was active.

## Step 7 — Recreate the Test File

The original test file was removed and recreated after FileCreate logging was enabled:

```powershell
Remove-Item "$env:USERPROFILE\Documents\CyberLab\Lab9\lab9-test.txt"
```

```powershell
"Cybersecurity Lab 9 file creation test" |
Set-Content "$env:USERPROFILE\Documents\CyberLab\Lab9\lab9-test.txt"
```

## Step 8 — Sysmon Event ID 11: File Create

A matching Event ID `11` was captured.

Verified fields:

- `TimeCreated: 8/18/2026 12:21:03 PM`
- `UtcTime: 2026-08-18 16:21:03.894`
- `ProcessId: 9280`
- `ProcessGuid: {44acc921-8651-6a84-ad02-000000000e00}`
- `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- `TargetFilename: C:\Users\User1\Documents\CyberLab\Lab9\lab9-test.txt`
- `User: LAB-ENDPOINT-01\User1`

Interpretation:

```text
powershell.exe
PID 9280
        ↓
Sysmon Event ID 11
        ↓
created lab9-test.txt
```

## Step 9 — Calculate the File SHA-256

The file hash was calculated with:

```powershell
Get-FileHash "$env:USERPROFILE\Documents\CyberLab\Lab9\lab9-test.txt" -Algorithm SHA256
```

Verified SHA-256:

```text
CECEB3F22E79D072CB63FBF6ECCBE3587AA8E150925B97E7290B856710AFD3C1
```

### Hash Interpretation

A filename is a label. A SHA-256 hash is a fingerprint of the file's contents.

If the file is renamed without changing its contents, its SHA-256 should stay the same. If the contents change, the hash should change.

A hash by itself does **not** prove that a file is malicious.

## Step 10 — Correlate Event ID 1 and Event ID 11

The Event ID `11` ProcessGuid was used to locate the matching Sysmon Event ID `1`.

Verified Event ID `1` fields:

- `TimeCreated: 8/18/2026 12:20:33 PM`
- `UtcTime: 2026-08-18 16:20:33.554`
- `ProcessId: 9280`
- `ProcessGuid: {44acc921-8651-6a84-ad02-000000000e00}`
- `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- `User: LAB-ENDPOINT-01\User1`
- `IntegrityLevel: Medium`
- `ParentProcessId: 5892`
- `ParentImage: C:\Windows\explorer.exe`

The same PID **and** ProcessGuid appeared in Event ID `1` and Event ID `11`.

Reconstructed activity:

```text
explorer.exe
        ↓
launches powershell.exe
PID 9280
ProcessGuid {44acc921-8651-6a84-ad02-000000000e00}
        ↓
Sysmon Event ID 11
        ↓
creates lab9-test.txt
        ↓
SHA-256
CECEB3F22E79D072CB63FBF6ECCBE3587AA8E150925B97E7290B856710AFD3C1
```

### Important Hash Distinction

The `Hashes:` field inside Sysmon Event ID `1` is the hash of the **process executable** (`powershell.exe`). It is not the hash of `lab9-test.txt`.

The test file's SHA-256 was calculated separately using `Get-FileHash`.

## Step 11 — Rename the File

The file was renamed:

```powershell
Rename-Item `
"$env:USERPROFILE\Documents\CyberLab\Lab9\lab9-test.txt" `
"renamed-lab9-file.txt"
```

The renamed file was hashed again:

```powershell
Get-FileHash `
"$env:USERPROFILE\Documents\CyberLab\Lab9\renamed-lab9-file.txt" `
-Algorithm SHA256
```

The SHA-256 remained exactly the same:

```text
CECEB3F22E79D072CB63FBF6ECCBE3587AA8E150925B97E7290B856710AFD3C1
```

### Analyst Conclusion

Changing the filename did not change the file contents, so the content hash remained unchanged.

This demonstrates why hashes are stronger than filenames when identifying exact file content.

## Final Analyst Finding

A normal-user PowerShell process (`PID 9280`, `IntegrityLevel: Medium`) was launched by `explorer.exe`. Sysmon Event ID `11` recorded that same process creating `lab9-test.txt`. The process and file events were directly correlated with both `ProcessId` and `ProcessGuid`. The file's SHA-256 was calculated and remained unchanged after the file was renamed, demonstrating the difference between a filename and a content fingerprint.

## Memory Recall

1. What does Sysmon Event ID `11` record?
2. Why did the first file creation produce no Event ID `11`?
3. What command showed the active Sysmon configuration?
4. Why was the Sysmon XML backed up before editing?
5. Which XML rule enabled Event ID `11` collection?
6. What fields directly correlated Event ID `1` and Event ID `11`?
7. Why is `ProcessGuid` useful in addition to PID?
8. What did `IntegrityLevel: Medium` mean in this exercise?
9. What does SHA-256 identify?
10. Does a hash alone tell you that a file is malicious?
11. Why did renaming the file not change its SHA-256?
12. What would happen to the SHA-256 if the file contents changed?
13. What does the hash in Sysmon Event ID `1` refer to?
14. How is that different from the hash calculated with `Get-FileHash`?

## Recall Goal

Be able to explain this chain without looking at the notes:

```text
Process creation
      ↓
File creation
      ↓
ProcessGuid/PID correlation
      ↓
File hash
      ↓
Content identity
```
