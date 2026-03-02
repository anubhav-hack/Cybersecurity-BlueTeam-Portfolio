# 🛡️ Carnage – Malware Traffic Analysis & C2 Investigation

---

## 1 Executive Summary

This report presents the analysis of suspicious network traffic captured in the `carnage.pcap` file using Wireshark.

The investigation identified a malicious infection chain involving the download of a ZIP archive from an external server, execution of macro-based malware, and subsequent encrypted Command & Control (C2) communication.

The compromised host (`10.9.23.102`) downloaded a malicious file (`documents.zip`) from `85.187.128.24`, which was later confirmed as malware (trojan.x97m/dloadr) through VirusTotal analysis.

Following execution, the infected system established persistent encrypted TLS communication with external IP `23.111.114.52` over TCP port `65400`, indicating active C2 behavior.

The findings confirm a successful malware infection and ongoing outbound C2 communication within the captured network traffic.

---

## 2 Incident Overview

- **Analysis Tool Used:** Wireshark
- **File Analyzed:** carnage.pcap
- **Date of Analysis:** 03-03-2026
- **Analyst:** Anubhav Kumar

---

## 3. Technical Analysis

---

## 3.1 Victim Identification

The internal host identified as compromised:

**Victim IP:** `10.9.23.102`

This system generated the highest volume of suspicious outbound traffic and was responsible for downloading the malicious payload.

---

## 3.2 Initial Compromise

The victim downloaded a ZIP file from an external server:

- **Domain:** `attirenepal.com`
- **External IP:** `85.187.128.24`
- **File Name:** `documents.zip`
- **Protocol:** HTTP
- **Response Status:** 200 OK
- **File Size:** ~198 KB

The successful HTTP 200 OK response confirms the malicious file was fully delivered to the victim system.

---

## 3.3 Malware Verification

The downloaded file was extracted and hashed.

**SHA256:**

77229c744a0b1470afc7989a774cfe821386c11c0165e7e3fb5e9897a789a8cb

VirusTotal analysis showed:

- **Detection Ratio:** 41 / 64 vendors
- **Threat Label:** trojan.x97m/dloadr
- **Category:** Trojan / Downloader
- **File Type:** ZIP (~193 KB)

This confirms the file is malicious and associated with macro-based downloader malware.

---

## 3.4 Post-Infection Activity

After the download, the victim initiated outbound encrypted communication to:

- **External IP:** `23.111.114.52`
- **Protocol:** TCP (TLSv1.2)
- **Port:** 65400
- **Packet Count:** 18,002
- **Traffic Type:** Encrypted persistent communication

The original download server (`85.187.128.24`) showed no further communication, indicating it acted only as the delivery server.

The large volume of encrypted TLS traffic over an uncommon high port strongly indicates Command & Control (C2) activity.

---

## 3.5 Payload Inspection Attempt

A search for visible encoded payloads over HTTP returned no results.

This is expected because the malware used encrypted TLS communication, preventing inspection of transmitted data.

---

## 4. Attack Chain Summary

1. Victim host identified (`10.9.23.102`)
2. Malicious ZIP downloaded from `85.187.128.24`
3. File confirmed malicious via VirusTotal
4. Malware executed on victim system
5. Encrypted C2 communication established with `23.111.114.52` over TCP port `65400`

---

## 5. MITRE ATT&CK Mapping

 - **T1566.001 – Phishing: Spearphishing Attachment**
- **T1204.002 – User Execution: Malicious File**
- **T1071.001 – Application Layer Protocol: Web Protocols**
- **T1573 – Encrypted Channel**
-  **T1095 – Non-Application Layer Protocol**
- **T1105 – Ingress Tool Transfer**

---


## 6. Final Conclusion

The PCAP confirms a successful malware infection on host `10.9.23.102`.

The attack involved:
- Malicious file delivery via HTTP
- Execution of macro-based downloader malware
- Persistent encrypted Command & Control communication

The external IP `23.111.114.52` is identified as the active C2 server.

---

**Investigation Status:** Confirmed Compromise & Active C2 Communication  
