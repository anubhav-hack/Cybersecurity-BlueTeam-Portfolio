#  Windows Authentication & Security Log Monitoring

##  Project Title
SOC Level 1 – Windows Security Event Monitoring & Analysis

##  Log Source
Windows Security Event Logs (`WinEventLog:Security`)

##  SIEM Platform
Splunk Enterprise

##  Dataset
BOTS v1 Dataset (`index=botsv1`)

##  Objective
To monitor and analyze Windows Security Event Logs in order to detect:

- Authentication-based attacks  
- Privilege escalation attempts  
- Suspicious process execution  
- Object access anomalies  
- Abnormal session behavior  

---

## 1️ Log Source Configuration

**Operating System Simulated:** Windows Server Environment  
**Log Channel:** `WinEventLog:Security`  
**Collection Method:** Splunk Universal Forwarder  
**Index Used:** `botsv1`

### Log Access Path (Native Windows View)

Event Viewer → Windows Logs → Security

---

## 2️ Critical Windows Security Event IDs (SOC Monitoring)

---

##  1. Successful Logon — Event ID 4624

### Description
Generated when a user successfully logs into a system.

### Important Fields
- Account_Name  
- Logon_Type  
- Source_Network_Address  
- Workstation_Name  

### Important Logon Types

| Logon Type | Meaning |
|------------|----------|
| 2 | Interactive (Local Login) |
| 3 | Network Login |
| 7 | Unlock |
| 10 | Remote Desktop (RDP) |
| 11 | Cached Login |



### Splunk Query

```
index=botsv1 source="WinEventLog:Security" EventCode=4624
| stats count by Account_Name, Logon_Type, Source_Network_Address
```
![Splunk Query](../screenshots/S1.png)


**Observations:**

- Logon_Type = 3 (Network Logon)

- IP 192.168.2.50 generating very high logins

- Administrator account active

- SYSTEM account present

- ANONYMOUS LOGON present

- Mostly internal IP addresses

### Detection Use Cases
- Suspicious RDP login (Logon Type 10)
- Login from unknown/external IP
- Login outside business hours

### MITRE ATT&CK
T1078 – Valid Accounts

---

## 2. Failed Credential Validation — Event ID 4776

### Description
Triggered when a domain controller attempts to validate account credentials using NTLM authentication.

This event records both successful and failed credential validation attempts in domain environments.

### Important Fields
- Account_Name  
- Source_Workstation  
- Status  
- Authentication_Package  



### Splunk Query Used

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4776
| stats count by status
```
![Splunk Query](../screenshots/S3.png)
---

### Findings

- Total Events: 2,384
- Authentication Result: **success**
- No failed credential validation attempts observed.

---

### Security Assessment

- No evidence of brute-force attempts.
- No password spraying detected.
- No incorrect password attempts identified.
- All credential validation events were successful.

---

### Conclusion

Analysis of Event ID 4776 indicates normal NTLM credential validation activity within the domain environment.

Since all events show successful authentication status and no failure indicators were detected, there is no evidence of authentication-based attack activity during the analyzed timeframe.

The authentication behavior appears consistent with legitimate domain operations.

---

## 3. Special Privileges Assigned — Event ID 4672

### Description
Event ID 4672 is generated when special privileges are assigned to a new logon session.

This event typically occurs when an account with administrative or elevated privileges successfully logs into a system.

It usually appears immediately after Event ID 4624 (Successful Logon).

---

### Splunk Query Used

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4672
| stats count by Account_Name
```
![Splunk Query](../screenshots/S2.png)

---

### Findings

| Account_Name     | Count |
|------------------|-------|
| Administrator    | 2382  |
| WE9041SRV$       | 659   |

---

### Analysis

- The majority of special privilege assignments were associated with the **Administrator** account.
- Machine account **WE9041SRV$** also shows significant privileged activity, likely representing domain controller or server authentication.
- SYSTEM and service accounts generated minimal events, consistent with expected system operations.

No abnormal or unknown user accounts were observed receiving elevated privileges.

---

### Detection Use Cases

- Monitoring administrative account logins
- Detecting potential privilege escalation
- Identifying unauthorized privileged access
- Correlating with suspicious process execution (Event ID 4688)

---

### MITRE ATT&CK Mapping

- T1078 – Valid Accounts  
- T1068 – Privilege Escalation  

---

### Security Assessment

The high volume of Event ID 4672 associated with the Administrator account appears consistent with administrative or domain-related activity.

No unexpected user accounts were observed receiving special privileges.

At this stage, there is no clear indication of privilege escalation abuse. However, continuous monitoring and correlation with:

- Event ID 4624 (Successful Logon)
- Event ID 4688 (Process Creation)

is recommended to detect suspicious administrative behavior.

---

### Conclusion

Event ID 4672 analysis indicates normal privileged account activity within the domain environment.

While elevated privileges were assigned primarily to the Administrator and system-related accounts, no anomalous or unauthorized privilege assignment activity was identified during the analysis period.

---

## 4. Process Creation Monitoring — Event ID 4688

### Description
Event ID 4688 is generated whenever a new process is created on a Windows system.

This event provides visibility into command execution and is critical for detecting:

- Malware execution
- Suspicious scripting activity
- Administrative tool abuse
- Post-compromise activity

---

### Splunk Query Used

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4688
| stats count by Account_Name, New_Process_Name
| sort - count
```
![Splunk Query](../screenshots/S4.png)
---

### Key Findings

High-frequency process executions were observed for the following executables:

| Account_Name | New_Process_Name | Count |
|-------------|------------------|-------|
| WE1149SRV$  | splunk-powershell.exe | 368 |
| WE9041SRV$  | splunk-powershell.exe | 368 |
| WE8105DESKS | splunk-powershell.exe | 318 |
| WE1149SRV$  | splunk-MonitorNoHandle.exe | 184 |
| WE1149SRV$  | splunk-admon.exe | 184 |
| WE1149SRV$  | splunk-netmon.exe | 184 |
| WE1149SRV$  | splunk-winprintmon.exe | 184 |

All processes were located under:

```
C:\Program Files\SplunkUniversalForwarder\bin\
```

---

### Analysis

The observed processes belong to the Splunk Universal Forwarder service.

These executables are responsible for:

- Log monitoring
- Network monitoring
- PowerShell data collection
- System telemetry gathering

The high frequency of execution is consistent with normal log collection operations in an enterprise environment.

No suspicious or unknown executables were identified during this analysis.

---

### Security Assessment

- No evidence of malicious process execution.
- No suspicious administrative command execution detected.
- All processes appear legitimate and system-related.

The activity is consistent with expected Splunk monitoring behavior.

---

### MITRE ATT&CK Mapping

T1059 – Command and Scripting Interpreter  
T1106 – Native API  

(Note: In this case, activity appears legitimate.)

---

### Conclusion

Event ID 4688 analysis identified repeated execution of Splunk Universal Forwarder components.

The behavior is consistent with normal system monitoring operations.

No indicators of malicious process execution were observed during the analysis period.

---

## 5. Object Access Attempt — Event ID 4656

### Description
Event ID 4656 is generated when a process requests access to a system object such as a file, registry key, or system resource.

This event records object access attempts but does not confirm whether access was granted.

---

### Splunk Query Used

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4656
| stats count by Account_Name, Process_Name, Object_Name
| sort - count
```
![Splunk Query](../screenshots/S5.png)
---

### Key Findings

High-frequency object access attempts were observed from the following processes:

| Account_Name | Process_Name | Object_Name |
|-------------|-------------|-------------|
| WE8105DESKS | vss_requestor.exe | C:\Windows\diagnostics |
| WE8105DESKS | vss_requestor.exe | C:\Windows\diagnostics\system |
| WE8105DESKS | vss_requestor.exe | C:\Windows\SystemResources |
| WE1149SRV$  | vmtoolsd.exe | \Device\floppy0 |

---

### Analysis

The process `vss_requestor.exe` belongs to Acronis backup software and is responsible for:

- Volume Shadow Copy operations
- Backup snapshot creation
- System file inspection

The process `vmtoolsd.exe` is part of VMware Tools and is responsible for virtualization-related system interactions.

The accessed objects are standard Windows system directories and virtual devices.

No access to high-risk objects such as:

- lsass.exe
- SAM
- NTDS.dit
- SYSTEM registry hive

was observed.

---

### Security Assessment

- Activity appears consistent with backup and virtualization operations.
- No evidence of credential dumping attempts.
- No suspicious object access to sensitive authentication stores.

This behavior is classified as **normal system activity**.

---

### MITRE ATT&CK Mapping

T1003 – Credential Dumping (Not observed in this case)  
T1106 – Native API  

---

### Conclusion

Event ID 4656 analysis indicates object access activity related to legitimate backup and virtualization processes.

No indicators of malicious object access or credential harvesting were identified during the analysis period.

---

## 6. Logoff Monitoring — Event ID 4634

### Description
Event ID 4634 is generated when a logon session is terminated.

This event indicates that a user or system session has ended and is typically correlated with Event ID 4624 (Successful Logon).

Monitoring logoff activity helps identify abnormal session patterns and authentication behavior.

---

### Splunk Query Used

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4634
| stats count by Account_Name, Logon_Type
```
![Splunk Query](../screenshots/S6.png)
---

### Key Findings

| Account_Name     | Logon_Type | Count |
|------------------|------------|-------|
| Administrator    | 3          | 2382  |
| WE9041SRV$       | 3          | 659   |
| ANONYMOUS LOGON  | 3          | 59    |
| WE8105DESKS$     | 3          | 45    |
| WE1149SRV$       | 3          | 17    |
| bob.smith        | 3          | 11    |
| DWM-3            | 2          | 4     |
| bob.smith        | 7          | 1     |

---

### Logon Type Interpretation

| Logon Type | Meaning |
|------------|----------|
| 2 | Interactive (Local Login) |
| 3 | Network Logon |
| 7 | Unlock Session |

The majority of logoff events were associated with **Logon Type 3 (Network Logon)**.

---

### Analysis

- High volume of network logoff events associated with the Administrator account.
- Machine accounts (ending with `$`) show expected network authentication behavior.
- ANONYMOUS LOGON activity appears minimal and consistent with normal network operations.
- No unusual interactive (Logon Type 2) patterns observed.
- No excessive RDP (Logon Type 10) activity detected.

The logoff distribution appears consistent with normal domain authentication operations.

---

### Security Assessment

- No abnormal login-logoff burst patterns detected.
- No indication of rapid authentication cycling.
- Activity appears consistent with expected network session lifecycle behavior.

Correlation with Event ID 4624 confirms balanced login and logoff activity.

---

### MITRE ATT&CK Mapping

T1078 – Valid Accounts  
T1021 – Remote Services  

---

### Conclusion

Event ID 4634 analysis indicates normal session termination behavior within the environment.

The majority of activity consists of network-based authentication sessions consistent with domain operations.

No suspicious or anomalous logoff patterns were identified during the analysis period.

# 4️ Recommended Dashboard Panels

- Total Successful Logins  
- Total Failed Logins  
- Failed Logins by IP  
- Account Lockouts  
- New User Creation  
- Privilege Escalation Attempts  
- Suspicious Process Execution  
- Log Clearance Alerts  
- Brute Force Detection  

---

# 5️ Security Monitoring Outcome

By monitoring these Windows Security logs, the SOC team can detect:

- Brute Force Attacks  
- Password Spray Attacks  
- Credential Compromise  
- Privilege Escalation  
- Unauthorized Account Creation  
- Insider Threat Activity  
- Suspicious Command Execution  
- Log Tampering  

---

# 6 Conclusion

Windows Security Event Logs provide critical visibility into authentication, privilege management, and process activity.  
Centralized monitoring in Splunk enables early detection of identity-based attacks and system compromise attempts.

This implementation aligns with SOC Level 1 monitoring standards and the MITRE ATT&CK framework.

