# 🎣 Phishing Email Analysis

Hands-on analysis of real-world phishing emails, written in the style of SOC (Security Operations Center) incident reports.

Each report covers the full investigation workflow a SOC analyst follows when a suspicious email is reported: header analysis, sender authentication (SPF / DKIM / DMARC), IP and domain reputation, URL analysis, identification of phishing techniques, IOC extraction, a final verdict and response recommendations.

---

## 📂 Reports

| # | Report | Impersonated brand | Type | Verdict |
|---|--------|--------------------|------|---------|
| 01 | [OTTO Brand Impersonation — Diet Pill Scam](./Report-01-OTTO-Impersonation/) | OTTO (otto.de) | Brand spoofing / Scam | 🔴 Phishing — High |

*More reports coming soon.*

---

## 🔍 Analysis Methodology

1. **Header analysis** — sender, Reply-To, envelope sender, Message-ID, mail server path
2. **Authentication checks** — SPF, DKIM and DMARC results and what they prove
3. **IP reputation** — owner, hosting type, abuse history
4. **URL & domain analysis** — extracting links from the raw email and checking them safely
5. **Technique mapping** — social engineering and evasion techniques used
6. **IOC extraction** — defanged indicators ready for blocking
7. **Verdict & response** — classification, risk level and SOC recommendations

---

## 🧰 Tools

| Tool | Purpose |
|------|---------|
| VirusTotal | IP, domain and URL reputation |
| AbuseIPDB | IP abuse reports, ISP and usage type |
| URLScan.io | Safe URL scanning and redirect analysis |
| MXToolbox | Email header analysis |
| CyberChef | Decoding (Base64, quoted-printable, etc.) |

---

## ⚠️ Safety Notice

- All samples come from the public research repository [rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot).
- All malicious indicators in the reports are **defanged** (`hxxp://`, `example[.]com`) to prevent accidental clicks.
- Emails were analyzed as raw text only. No links were opened and no attachments were executed on a host system.
- This repository is for **educational and research purposes only**.

---

## 👤 Author

**Shodiyor Tuychivoyev** — aspiring SOC Analyst

<!-- Add your LinkedIn / TryHackMe links here -->
