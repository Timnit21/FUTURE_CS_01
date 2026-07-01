# 🛡️ Task 1: Enterprise Vulnerability Assessment & Network Infrastructure Reconnaissance Report

**Target Environment:** scanme.nmap.org  
**Assigned Track Code:** CS (Cyber Security)  
**Security Framework Alignment:** OWASP Top 10 Web Application Security Risks & NIST SP 800-115  
**Document Classification:** Technical Evaluation / Restricted  
**Prepared By:** Intern - Cyber Security  
**Date of Assessment:** July 1, 2026  

---

## 1. Executive Summary
An external, non-intrusive vulnerability assessment and architectural reconnaissance operation was conducted against the authorized asset `scanme.nmap.org`. The structural focus was to safely map out network perimeter exposures, discover active host daemons, identify software version leaks, and audit client-side web application container defenses. 

The evaluation was executed in strict conformance with the **NIST SP 800-115** technical security testing model. The asset maintains a stable baseline configuration; however, critical omissions in HTTP defense headers and public exposures of legacy remote administration protocols present an exploitable posture. If leveraged by a sophisticated threat actor, these structural flaws allow precise profiling, automated brute-force infrastructure mapping, and client-side code execution vulnerabilities. Immediate remediation is required to minimize the attack vector.

---

## 2. Scope of Assessment & Target Blueprint
The scope of this technical engagement is locked strictly to the following parameters. No out-of-scope pivots were performed.

| Scope Attribute | Technical Specification Details |
| :--- | :--- |
| **Primary Target URL** | `http://scanme.nmap.org` / `https://scanme.nmap.org` |
| **Resolved IPv4 Address** | `45.33.32.156` |
| **Target Infrastructure Host** | Linode LL-LLC Cloud Network Infrastructure |
| **Testing Window** | July 1, 2026 – July 3, 2026 |
| **Assessment Methodology** | Black-box external passive scanning & service fingerprinting |

---

## 3. Methodology & Tooling Framework
To maximize verification accuracy and eliminate false positives, an integrated multi-tier scanning architecture was deployed:

1. **Network Layer Reconnaissance (Nmap 7.92+):** Executed low-intensity TCP SYN scans alongside advanced service version detection protocols to query layer-4 transport states.
2. **Application Layer Inspection (OWASP ZAP 2.14+):** Configured as a passive intercepting proxy to parse downstream HTTP response headers, validating the session layer without modifying active packet streams.
3. **Manual Browser Diagnostics Framework:** Used integrated developer inspector networks to analyze raw security header tokens and cookies transmitted from the destination web engine.

---

## 4. Quantitative Vulnerability Risk Matrix
Vulnerabilities are mathematically weighted using the **Common Vulnerability Scoring System (CVSS v3.1)** standard metrics:

| Finding ID | Vulnerability Classification | CVSS v3.1 Vector String | Base Score | Severity | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01-001** | Public Exposure of SSH Remote Daemon | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | **5.3** | **Medium** | Open |
| **SEC-01-002** | HTTP Server Banner Information Leakage | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | **5.3** | **Medium** | Open |
| **SEC-01-003** | Absence of Content-Security-Policy (CSP) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | **6.1** | **Medium** | Open |

---

## 5. Deep Technical Findings, Analysis & Remediation

### 🔍 SEC-01-001: Public Exposure of SSH Remote Management Service (Port 22)
* **Risk Severity Rating:** Medium (CVSS Base: 5.3)
* **Technical Discovery Analysis:** During network-tier probing using Nmap service verification parameters, Port `22/TCP` was identified as open, actively advertising a production-tier banner: `OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13`. This deployment is exposed directly to global inbound requests.
* **Exploitation & Business Impact:** Leaving the primary terminal control door open allows threat actors to perform automated password-spraying and dictionary brute-force campaigns. If access credentials are weak, an adversary can achieve an interactive shell connection, leading to full system compromise, malware injection, and internal pivoting.
* **Remediation Pattern (Production Hardening):**
  1. Restrict all incoming traffic to Port 22 via strict host-based firewall policies (`iptables` or cloud security groups), permitting exclusively whitelisted administrator source IPs.
  2. Modify the SSH configuration directive inside `/etc/ssh/sshd_config` to turn off password-based authentication and enforce asymmetric keys:
     ```text
     PasswordAuthentication no
     PermitRootLogin no
     PubkeyAuthentication yes
     ```

---

### 🔍 SEC-01-002: HTTP Server Banner Information Leakage
* **Risk Severity Rating:** Medium (CVSS Base: 5.3)
* **Technical Discovery Analysis:** Analysis of response tokens returned during passive HTTP handshakes confirmed that the backend ecosystem loudly broadcasts its system-tier identities: `Apache/2.4.7 ((Ubuntu))`.
* **Exploitation & Business Impact:** Verbose headers give attackers critical intelligence. By reviewing this metadata, a malicious actor can instantly query public vulnerability indexes (like CVE/NVD databases) for unpatched buffer overflows or remote code execution (RCE) vectors that match Apache 2.4.7 specifically, significantly speeding up their weaponization timeline.
* **Remediation Pattern (Production Hardening):**
  Access the core configuration interface of the web routing node (`/etc/apache2/apache2.conf` or equivalent) and append the following directives to redact operational information:
  ```apache
  ServerTokens Prod
  ServerSignature Off
  Content-Security-Policy: default-src 'self'; script-src 'self' [https://trusted-cdn.com](https://trusted-cdn.com); object-src 'none'; frame-ancestors 'none';
  $ nmap -sV -p 22,80 -T4 scanme.nmap.org

Starting Nmap 7.92 ( [https://nmap.org](https://nmap.org) ) at 2026-07-01 15:34 EAT
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.12s latency).
rDNS record for 45.33.32.156: netor.idles.org

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))

Service detection performed. 1 IP address (1 host up) scanned in 4.89 seconds.
HTTP/1.1 200 OK
Date: Wed, 01 Jul 2026 15:35:12 GMT
Server: Apache/2.4.7 (Ubuntu)
Last-Modified: Fri, 19 May 2023 12:04:11 GMT
ETag: "2d1-5fc399e1a1c00"
Accept-Ranges: bytes
Content-Length: 721
Connection: close
Content-Type: text/html

<!DOCTYPE html> ... [Web Content Body]
