# SOC Detection Engineering Lab – PowerShell Encoded Command Detection

## Overview

This project demonstrates an end-to-end SOC workflow focused on detecting suspicious PowerShell activity using Sysmon, Wazuh, and TheHive. The lab simulates a real-world attack scenario based on MITRE ATT&CK T1059.001 (PowerShell) using Atomic Red Team.

The objective of this lab is to validate how endpoint telemetry can be collected, parsed, correlated, and escalated into actionable alerts for incident triage and threat hunting activities.

---

# Lab Environment

| Component | Description |
|---|---|
| Windows 10 VM | Target endpoint |
| Sysmon | Endpoint telemetry collection |
| Wazuh Agent | Log forwarding |
| Wazuh Manager | SIEM & detection engine |
| OpenSearch Dashboard | Threat hunting & visualization |
| TheHive | Incident response platform |
| Atomic Red Team | Attack simulation framework |

---

# Architecture

![Architecture Diagram](./images/Architecture.png)

---

# Attack Simulation

The attack simulation was performed using Atomic Red Team with technique:

- MITRE ATT&CK: T1059.001
- Technique: PowerShell

The test generated encoded PowerShell execution activity to simulate suspicious command execution commonly observed during post-exploitation stages.

Example execution:

```powershell
Invoke-AtomicTest T1059.001
