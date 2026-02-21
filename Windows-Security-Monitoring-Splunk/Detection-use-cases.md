#  Detection Use Cases

The following detection use cases were implemented using Windows Security Event Logs in Splunk to identify potential security threats and abnormal behavior.

---

##  1. Brute Force & Password Spray Detection

**Relevant Events:**  
- 4624 – Successful Logon  
- 4776 – Credential Validation  

**Detection Logic:**

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4776
| stats count by user, Source_Workstation
| where count > 10
```

**Objective:**
Detect repeated authentication attempts from a single host targeting one or multiple accounts.

---

##  2. Suspicious Successful Logon

**Relevant Event:**  
- 4624 – Successful Logon  

**Detection Logic:**

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4624
| stats count by Account_Name, Logon_Type, Source_Network_Address
```

**Objective:**
Identify:
- Unusual login types (e.g., RDP – Logon Type 10)
- Unknown source IP addresses
- High-volume network logons

---

## 3. Privileged Account Monitoring

**Relevant Event:**  
- 4672 – Special Privileges Assigned  

**Detection Logic:**

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4672
| stats count by Account_Name
```

**Objective:**
Monitor when administrative or system-level privileges are assigned to user accounts.

---

##  4. Suspicious Process Execution

**Relevant Event:**  
- 4688 – Process Creation  

**Detection Logic:**

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*powershell*" OR New_Process_Name="*cmd*" OR New_Process_Name="*wscript*"
| stats count by Account_Name, New_Process_Name
```

**Objective:**
Detect:
- PowerShell abuse
- Command-line execution
- Script-based attacks
- Potential malware execution

---

##  5. Sensitive Object Access Detection

**Relevant Event:**  
- 4656 – Object Access Attempt  

**Detection Logic:**

```spl
index=botsv1 source="WinEventLog:Security" EventCode=4656
| search Object_Name="*lsass*" OR Object_Name="*SAM*" OR Object_Name="*NTDS*"
```

**Objective:**
Detect potential credential dumping or unauthorized access to sensitive system files.

---

##  6. Abnormal Session Lifecycle Detection

**Relevant Events:**  
- 4624 – Successful Logon  
- 4634 – Logoff  

**Detection Logic:**

```spl
index=botsv1 source="WinEventLog:Security" (EventCode=4624 OR EventCode=4634)
| stats count by EventCode, Account_Name
```

**Objective:**
Detect:
- Rapid login-logoff behavior
- Missing logoff events
- Abnormal session duration

---

##  7. Log Tampering Detection

**Relevant Event:**  
- 1102 – Audit Log Cleared  

**Detection Logic:**

```spl
index=botsv1 source="WinEventLog:Security" EventCode=1102
```

**Objective:**
Detect attempts to clear Windows Security logs, which may indicate attacker activity.

---
