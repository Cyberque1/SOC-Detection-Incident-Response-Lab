# Lab 14 — Wazuh SIEM and Centralized Windows Telemetry

## Objective

Deploy a Wazuh SIEM server, enroll the monitored Windows endpoint, centralize endpoint telemetry, and verify that Sysmon, PowerShell, and Microsoft Defender events generated on `LAB-ENDPOINT-01` are searchable from the Wazuh dashboard.

## Environment and Tools

- `LAB-ENDPOINT-01` — Windows 11 Pro, `192.168.64.2`
- `LAB-WAZUH-01` — Ubuntu Server / Wazuh all-in-one deployment, `192.168.64.4`
- Wazuh agent `4.14.7`
- Sysmon
- PowerShell Script Block Logging
- Microsoft Defender Antivirus
- Wazuh Manager, Indexer, Dashboard, and Filebeat

## Agent Enrollment and Connectivity

The Wazuh Windows agent was installed on `LAB-ENDPOINT-01` and configured to communicate with the Wazuh manager at `192.168.64.4`.

Connectivity was validated before enrollment:

- ICMP communication between the Windows endpoint and Wazuh server succeeded.
- TCP `1514` and `1515` connectivity from the endpoint to the Wazuh server succeeded.
- The Windows `WazuhSvc` service was verified as running.
- The Wazuh dashboard reported the endpoint as active.

Verified agent identity:

- Agent ID: `001`
- Name: `Lab-Endpoint-01`
- IP: `192.168.64.2`
- Operating system: Windows 11 Pro
- Status: `active`

## Telemetry Configuration

The default Wazuh Windows agent collected the standard Windows `Application`, `Security`, and `System` event channels. Additional SOC telemetry was configured through the agent `ossec.conf` file using Windows event-channel collection.

Additional channels enabled:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

The Wazuh agent log confirmed that each configured channel was actively analyzed.

## Raw Event Indexing

Not every useful endpoint event generates a Wazuh alert. To support investigation of low-severity and non-alerting telemetry, JSON event archiving was enabled on the manager and Filebeat archive forwarding was enabled.

This created a searchable `wazuh-archives-*` data source in the Wazuh dashboard, allowing analysts to investigate raw endpoint telemetry in Discover.

## Sysmon Verification

A controlled command was executed on the Windows endpoint:

```powershell
cmd.exe /c echo LAB14-SIEM-TEST
```

Sysmon recorded the activity as Event ID `1` and Wazuh successfully ingested and indexed the event.

Centralized evidence included:

- Agent: `Lab-Endpoint-01`
- Source IP: `192.168.64.2`
- Channel: `Microsoft-Windows-Sysmon/Operational`
- Event ID: `1`
- Process: `C:\Windows\System32\cmd.exe`
- Command line: `"C:\WINDOWS\system32\cmd.exe" /c echo LAB14-SIEM-TEST`
- User: `LAB-ENDPOINT-01\User1`

This verified the complete Sysmon path from endpoint generation through centralized SIEM search.

## PowerShell Verification

A unique PowerShell marker was generated:

```powershell
$LAB14PS="LAB14-POWERSHELL-TEST"; Write-Output $LAB14PS
```

The endpoint locally recorded PowerShell Event ID `4104`, and the exact event was identified in Wazuh using its ScriptBlock ID.

Centralized evidence included:

- Agent: `Lab-Endpoint-01`
- Channel: `Microsoft-Windows-PowerShell/Operational`
- Event ID: `4104`
- ScriptBlock ID: `7d2fbf35-cb99-4c48-815f-10c1a3c2a9f7`
- ScriptBlock text: `$LAB14PS="LAB14-POWERSHELL-TEST"; Write-Output $LAB14PS`

![Wazuh Discover showing PowerShell Event ID 4104 and LAB14-POWERSHELL-TEST script block](../evidence/01-wazuh-powershell-4104.png)

*Wazuh Discover showing centralized PowerShell Event ID `4104` from `Lab-Endpoint-01`, including the captured `LAB14-POWERSHELL-TEST` script block.*

This demonstrated centralized visibility into PowerShell script content rather than relying only on process metadata.

## Microsoft Defender Verification

The industry-standard EICAR antivirus test artifact was used to safely trigger Microsoft Defender Real-Time Protection.

Local Defender telemetry showed:

- Event ID `1116` — threat detected
- Event ID `1117` — remediation action completed
- Threat: `Virus:DOS/EICAR_Test_File`
- Severity: `Severe`
- Detection source: Real-Time Protection
- File path: `C:\Users\User1\Documents\CyberLab\Lab14\EICAR.txt`
- Remediation: quarantine
- Result: no additional actions required

The corresponding Defender event was then located in Wazuh using the Windows event ID and endpoint identity. The centralized record included the same threat identifier, severity, endpoint, and file path.

![Wazuh Discover showing Microsoft Defender EICAR detection for Lab-Endpoint-01](../evidence/02-wazuh-defender-detection.png)

*Microsoft Defender Event ID `1116` indexed in Wazuh, showing the controlled EICAR detection with endpoint, severity, threat, and file-path context.*

## Findings

The lab established a functional centralized Windows security-monitoring pipeline. The Windows endpoint successfully forwarded Sysmon, PowerShell, and Microsoft Defender telemetry to Wazuh, and the events were searchable through the SIEM dashboard.

A key operational lesson was that alert-only views are not sufficient for complete investigations. Enabling searchable raw archives allowed low-severity and non-alerting events such as routine Sysmon process creation to remain available for threat hunting and correlation.

## Skills Demonstrated

- Wazuh SIEM deployment and administration
- Windows endpoint agent enrollment
- SIEM connectivity validation
- Windows event-channel ingestion
- Sysmon centralized telemetry analysis
- PowerShell Event ID `4104` analysis
- Microsoft Defender Event ID `1116` and `1117` analysis
- Raw-event indexing and investigation
- Filebeat-to-indexer validation
- Endpoint-to-SIEM event correlation
- Threat-hunting workflow using Wazuh Discover
- Centralized security telemetry validation
