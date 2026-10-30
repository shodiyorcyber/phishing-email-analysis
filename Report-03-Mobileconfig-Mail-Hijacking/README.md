# Phishing Email Analysis — Sample 6997

| Field | Value |
|-------|-------|
| **Sample source** | [rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot) — `sample-6997.eml` |
| **Analyst** | Shodiyor Tuychivoyev |
| **Analysis date** | 30 October 2026 |
| **Verdict** | 🔴 **Phishing — Malicious attachment (mail hijacking) — High risk** |

> ⚠️ All malicious domains and email addresses in this report are **defanged** (`[.]`, `[@]`) to prevent accidental use.

---

## 1. Summary

This email uses a fake security alert — "New Login Attempt Detected – Please Review Your Account Activity" — to scare the user into installing two attachments.

What makes this sample interesting is that it **passes all authentication checks** (SPF, DKIM and DMARC all pass). So this is not a spoofed email — it was really sent from the `restosenligne.com` domain through Google Workspace. The domain itself is old and clean, which suggests a **compromised account** being abused to send phishing.

The real attack is not in the links (they point to the legitimate `restosenligne.com`), but in the two `.mobileconfig` attachments. These are Apple configuration profiles that, if installed, secretly set up the victim's **email and contacts** to go through an attacker-controlled server (`mail.blutr.gr`). This lets the attacker read the victim's emails and contacts.

---

## 2. Email Details

| Field | Value |
|-------|-------|
| **From (display)** | `mail.info.dz[@]restosenligne.com` |
| **Return-Path / Envelope sender (smtp.mailfrom)** | `mail.info.dz[@]restosenligne.com` |
| **Recipient (To)** | `customer-BkzhdFS[@]gemini.com` |
| **Subject (decoded from Base64)** | New Login Attempt Detected – Please Review Your Account Activity |
| **Date** | Sun, 4 May 2025 17:20:47 UTC |
| **Sender IP** | `209.85.218.102` |
| **Sender hostname** | `mail-ej1-f102.google.com` |
| **Message-ID domain** | `email.amazonses.com` |
| **Content-Type** | `multipart/mixed` (email with attachments) |

**Note:** the subject was encoded in Base64 (`=?UTF-8?B?...?=`) and decoded with CyberChef.

---

## 3. Header Analysis

**Authentication results:**

```
spf=pass (sender IP is 209.85.218.102) smtp.mailfrom=restosenligne.com;
dkim=pass (signature was verified) header.d=millpondvillage-net.20230601.gappssmtp.com;
dmarc=pass action=none header.from=restosenligne.com; compauth=pass reason=100
```

| Check | Result | Meaning |
|-------|--------|---------|
| **SPF** | ✅ pass | IP 209.85.218.102 is allowed to send for `restosenligne.com` |
| **DKIM** | ✅ pass | The signature is valid |
| **DMARC** | ✅ pass | The From domain aligns with the sending domain |

**Key findings:**

- **All authentication passed** — this email is *not* spoofed. It was really sent from `restosenligne.com`.
- **DKIM signing domain is different.** SPF is for `restosenligne.com`, but DKIM is signed by `millpondvillage-net...gappssmtp.com` (a different Google Workspace organization). This mismatch suggests the email was sent through another account and points to a **compromised or abused account**.
- **Message-ID mismatch.** The Message-ID uses `email.amazonses.com` (Amazon), but the email was actually sent from Google. This inconsistency is suspicious.

---

## 4. IP & Domain Reputation

### Sender IP — `209.85.218.102`

| Source | Result |
|--------|--------|
| VirusTotal | 0/92 — clean |
| AbuseIPDB | 341 reports, but 0% confidence; IP is whitelisted ("Google non-cloud IPs") |
| ISP / ASN | Google LLC, AS15169 |
| Hostname | `mail-ej1-f102.google.com` |

This is a **shared Google mail server**, so the reports belong to other spam sent through Google, not to this specific email. The IP reputation is inconclusive and cannot be used to block.

### Sending domain — `restosenligne[.]com`

| Source | Result |
|--------|--------|
| VirusTotal | 0/92 — clean |
| WHOIS | Created 1 May 2004 (22 years old), Registrar GoDaddy |
| URLScan | Resolves to `192.185.20.172` (Oracle Cloud, US); no classification |

The domain is old and clean. Attackers rarely own domains this old, which again points to a **legitimate domain / account that was compromised** and used to send phishing.

---

## 5. URL Analysis

The following links were found in the HTML body:

| # | URL (defanged) | Notes |
|---|----------------|-------|
| 1 | `hxxps://www[.]restosenligne[.]com/subscription?fbclid=...` | Points to the legitimate domain |
| 2 | `hxxp://restosenligne[.]com/contact/abuse?id=...` | Unsubscribe / tracking link with the recipient ID |

The links are not the attack — they go to the real `restosenligne.com`, which is clean. URLScan showed no malicious classification. The attack is in the attachments instead.

---

## 6. Attachment Analysis (the main attack)

The email contained two attachments:

- `email-fastpakco.mobileconfig`
- `carddav-fastpakco.mobileconfig`

A `.mobileconfig` file is an **Apple configuration profile** for iPhone/Mac. The Base64 content was decoded with CyberChef. The profile is of type `com.apple.mail.managed` (a managed mail account) and sets up the following:

| Setting | Value |
|---------|-------|
| Account / Email | `blutrgr[@]eu40.1host[.]gr` |
| Incoming server (IMAP) | `mail.blutr[.]gr` : 993 (SSL) |
| Outgoing server (SMTP) | `mail.blutr[.]gr` : 465 (SSL) |
| Organization | `eu40.1host[.]gr` |
| Display name | "Secure Email Setup" |

**What this does:** if the victim installs the profile (thinking they are "securing" their account), their device is configured to send and receive mail through the attacker-controlled server `mail.blutr.gr`. The second profile uses **CardDAV**, which does the same thing for the victim's **contacts**. Together, the attacker can read the victim's emails and steal their contacts.

The profile is also **digitally signed** with a Let's Encrypt certificate for `*.blutr.gr` (valid Feb–May 2025), which makes it look more trustworthy to the victim. `blutr.gr` and `1host.gr` (a Greek hosting provider) are likely compromised accounts used as attacker infrastructure.

---

## 7. Phishing Techniques Observed

| Technique | Evidence |
|-----------|----------|
| **Fear / urgency lure** | "New Login Attempt Detected – Please Review Your Account Activity" |
| **Malicious configuration profile** | `.mobileconfig` attachments that reconfigure mail and contacts |
| **Mail & contacts hijacking** | Managed mail (IMAP/SMTP) + CardDAV pointing to attacker server |
| **Abuse of a legitimate account** | Email passes SPF/DKIM/DMARC, sent from an old clean domain |
| **Signed payload** | Profile signed with a Let's Encrypt certificate to look legitimate |
| **Base64-encoded subject** | Subject hidden in Base64 encoding |

**MITRE ATT&CK mapping:**

| ID | Technique |
|----|-----------|
| T1566.001 | Phishing: Spearphishing Attachment |
| T1114 | Email Collection |

---

## 8. Indicators of Compromise (IOCs)

| Type | Value | Verdict |
|------|-------|---------|
| Domain | `blutr[.]gr` | **Malicious** — attacker mail server |
| Host | `mail.blutr[.]gr` | **Malicious** — IMAP/SMTP server in the profile |
| Domain | `eu40.1host[.]gr` | Suspicious — account domain in the profile |
| Email | `blutrgr[@]eu40.1host[.]gr` | Suspicious — account configured by the profile |
| Email | `mail.info.dz[@]restosenligne[.]com` | Suspicious — sending address (likely compromised) |
| File | `email-fastpakco.mobileconfig` | **Malicious** — mail hijacking profile |
| File | `carddav-fastpakco.mobileconfig` | **Malicious** — contacts hijacking profile |

> Note: `restosenligne.com` and the Google IP are legitimate and should **not** be blocked at the domain/IP level.

---

## 9. Verdict

| | |
|---|---|
| **Classification** | Phishing — malicious attachment (mail/contacts hijacking) |
| **Risk level** | 🔴 High |
| **Confidence** | High |

**Reasoning:** although the email passes all authentication (likely from a compromised account), it uses a fake security alert to trick the user into installing two malicious `.mobileconfig` profiles. If installed, these route the victim's email and contacts through an attacker-controlled server, giving the attacker full access to their communications.

---

## 10. Recommendations

1. **Block IOCs** — add `blutr.gr`, `mail.blutr.gr` and `eu40.1host.gr` to the email gateway and web proxy blocklists.
2. **Search & Purge** — find and remove all emails with the same sender, subject or attachments from user mailboxes.
3. **Check for installed profiles** — on managed devices (MDM), check whether any device installed the `.mobileconfig` profile and remove it.
4. **Respond to affected users** — if a user installed the profile, remove it, reset their account password, and review their mailbox for unauthorized access.
5. **User awareness** — warn users never to install configuration profiles (`.mobileconfig`) from emails, and that real login alerts should be checked directly on the official website/app.
6. **Improve detection** — flag emails that contain `.mobileconfig` attachments, since legitimate companies rarely send these by email.

---

## 11. Tools Used

- **GitHub Raw view** — reading email headers and body
- **CyberChef** — decoding the Base64 subject and the Base64 attachment
- **VirusTotal** — IP and domain reputation
- **AbuseIPDB** — IP abuse reports and ISP info
- **URLScan.io** — URL and domain scanning
- **WHOIS** — domain registration details
