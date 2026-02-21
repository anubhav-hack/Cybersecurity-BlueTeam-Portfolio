#  Incident Report – Suspicious Authentication & Privileged Activity

---

##  Incident Summary

| Field | Details |
|-------|---------|
| **Case ID** | IR-001 |
| **Date of Investigation** | 21 Feb 2026 |
| **Analyst Name** | Anubhav Kumar |
| **Severity Level** | Medium |
| **Status** | Closed (Lab Simulation) |
| **Data Source** | botsv1 (Splunk Dataset) |

---

#  Executive Summary

During routine monitoring of the Windows Security Dashboard, unusual authentication behavior was observed, including:

- High number of successful logons
- Multiple privileged logon events (4672)
- Suspicious PowerShell and CMD execution (4688)
- Sensitive object access attempts (4656)

Further analysis was conducted to determine whether the activity indicated potential credential misuse or lateral movement.

The investigation determined this activity was part of the dataset simulation, but the behavior mimics real-world attack patterns.

---

#  Detection Details

## 1 High Authentication Volume (Event ID 4624)

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4624
| stats count by Account_Name
| sort - count
| head 10
```

### Findings:
- Administrator account showed highest login volume.
- SYSTEM and service accounts also showed elevated activity.
- Authentication spike observed on timeline panel.

### Risk:
Potential compromised valid account (MITRE T1078 – Valid Accounts)

---

## 2 Privileged Logon Activity (Event ID 4672)

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4672
| stats count by Account_Name
```

### Findings:
- Administrator received special privileges multiple times.
- Indicates administrative token assignment.

### Risk:
Privilege Escalation activity.

---

## 3 Suspicious Process Execution (Event ID 4688)

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*powershell*" OR New_Process_Name="*cmd.exe*" OR New_Process_Name="*wscript*"
| stats count by New_Process_Name
```

### Findings:
- PowerShell executed multiple times.
- CMD execution observed.
- WScript activity detected.

### Risk:
Possible malicious script execution or lateral movement.

MITRE Mapping:
- T1059 – Command and Scripting Interpreter

---

## 4 Sensitive Object Access (Event ID 4656)

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4656
| search Object_Name="*SAM*" OR Object_Name="*NTDS*" OR Object_Name="*lsass*"
| stats count by Object_Name
```

### Findings:
- Access attempts to SAM registry.
- LSASS-related object interaction observed.

### Risk:
Credential Dumping Attempt (MITRE T1003)

---

## 5 Top Source IP Analysis

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4624
| stats count by Source_Network_Address
| sort - count
| head 10
```

### Findings:
- Internal IP (192.168.x.x) generated majority of activity.
- Loopback (::1, 127.0.0.1) present.
- No external brute-force detected in dataset.

---

#  Timeline Analysis

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4624
| timechart count
```

### Observation:
- Noticeable spike in authentication activity on specific date.
- Correlates with elevated PowerShell execution.

---

#  Impact Assessment

| Category | Assessment |
|----------|-----------|
| Data Exposure | None (Lab Dataset) |
| Privilege Escalation | Observed |
| Credential Access | Attempted |
| Lateral Movement | Possible |
| System Compromise | Not Confirmed |

---

#  Actions Taken

- Verified account activity
- Correlated process execution logs
- Reviewed sensitive object access
- Checked source IP distribution
- Confirmed dataset simulation environment

---

#  Recommendations

If this were a real production environment:

1. Reset Administrator credentials immediately
2. Review PowerShell command logs
3. Enable enhanced PowerShell logging
4. Investigate LSASS access attempts
5. Implement account lockout policy
6. Monitor privileged accounts continuously
7. Deploy EDR solution

---

#  Lessons Learned

- Authentication spikes must always be correlated with process execution.
- Privileged logons require immediate scrutiny.
- PowerShell remains a high-risk attack vector.
- Sensitive object access is a strong credential dumping indicator.

---

#  MITRE ATT&CK Mapping

| Technique | ID |
|------------|----|
| Valid Accounts | T1078 |
| Command & Scripting Interpreter | T1059 |
| Credential Dumping | T1003 |
| Privilege Escalation | TA0004 |
| Lateral Movement | TA0008 |

---

#  Conclusion

The activity observed in the Splunk dashboard demonstrates realistic attack behavior including:

- High authentication volume
- Privileged token assignment
- Suspicious PowerShell execution
- Credential access indicators

Although this was conducted within a simulated dataset, the detection logic mirrors real-world SOC investigations.

This investigation demonstrates practical SOC Level 1 skills including:

- Log analysis
- Event correlation
- Threat detection
- Risk assessment
- Incident documentation

---

 Prepared by: Anubhav Kumar  
 SOC Level 1 Threat Detection Portfolio