# Phishing Email Analysis — Sample 1153

| Field | Value |
|-------|-------|
| **Sample source** | [rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot) — `sample-1153.eml` |
| **Analyst** | Shodiyor Tuychivoyev |
| **Analysis date** | 25 September 2026 |
| **Verdict** | 🔴 **Phishing / Scam — High risk** |

> ⚠️ All malicious URLs and domains in this report are **defanged** (`hxxp`, `[.]`) to prevent accidental clicks.

---

## 1. Summary

This email impersonates **OTTO** (`otto.de`), a well-known German online retailer, to promote a fake weight-loss product called "KetoXplode Gummies". KetoXplode is not an OTTO product; the brand name is used only to gain the recipient's trust.

Header analysis shows that the email was **not sent by OTTO**: it failed SPF, DKIM and DMARC checks, was sent from a data-center hosting IP with a randomly generated hostname, and all replies are redirected to an attacker-controlled domain (`winner-win.art`). The email body contains links hidden behind a URL shortener and links to `firiri.shop`, a domain flagged as phishing by 12 security vendors on VirusTotal.

---

## 2. Email Details

| Field | Value |
|-------|-------|
| **From (display)** | KetoXplode Gummies Diet V_3 🧴🤸 `<otto-newsletter@newsletter.otto.de>` |
| **Reply-To** | `reply_to@winner-win[.]art` |
| **Envelope sender (smtp.mailfrom)** | `winner-win[.]art` |
| **Message-ID domain** | `winner-win[.]art` |
| **Subject** | Personalisierte Prognose für schnellen Gewichtsverlust ✅⏳ |
| **Subject (English)** | "Personalized prediction for fast weight loss" |
| **Received by Outlook** | Tue, 22 Aug 2023 19:55:15 UTC |
| **Sender IP** | `80.96.157[.]91` |
| **Sender hostname (HELO)** | `qktfxzqsjmwfnksijbkrjpmhgadbswa.whskk2` |
| **Recipient** | Redacted by sample repository (`phishing@pot`) |

---

## 3. Header Analysis

**Authentication results:**

```
spf=softfail (sender IP is 80.96.157.91) smtp.mailfrom=winner-win.art;
dkim=none (message not signed) header.d=none;
dmarc=fail action=none header.from=newsletter.otto.de;
```

| Check | Result | Meaning |
|-------|--------|---------|
| **SPF** | ❌ SoftFail | SPF checks the envelope sender domain (`winner-win.art`), not the visible From address. Even the attacker's own domain does not list `80.96.157.91` as an authorized sender. |
| **DKIM** | ❌ None | The message has no digital signature. Legitimate newsletters from large companies are normally DKIM-signed. |
| **DMARC** | ❌ Fail | The visible From domain (`newsletter.otto.de`) does not align with the actual sending domain (`winner-win.art`). This is clear evidence of **sender spoofing**. |

**Key findings:**

- **From / Reply-To mismatch.** The From address claims to be OTTO, but Reply-To, the envelope sender and the Message-ID all point to `winner-win.art`. Any reply from the victim would go to the attacker, not to OTTO.
- **Suspicious sending server.** The sending host identified itself as `qktfxzqsjmwfnksijbkrjpmhgadbswa.whskk2`, a random, meaningless string that is not a valid public hostname. This pattern is typical of spam infrastructure and botnets, not of legitimate corporate mail servers.

---

## 4. IP Reputation — `80.96.157[.]91`

| Source | Result |
|--------|--------|
| **VirusTotal** | 0/91 — no vendor flagged the IP. Network `80.96.156.0/22`, AS9009 (M247 Europe SRL), US |
| **AbuseIPDB** | Not found in database — 0 reports, 0% confidence of abuse |
| **ISP** | Virtono Networks SRL (`virtono.ro`) |
| **Usage type** | Data Center / Web Hosting / Transit |
| **Location** | Los Angeles, California, United States |

**Note on ISP difference:** VirusTotal shows **M247 Europe SRL**, the owner of the network (AS9009), while AbuseIPDB shows **Virtono Networks SRL**, a hosting provider that rents IP space from that network. Both are correct at different levels.

**Why a "clean" result does not mean safe:**

- The email was sent in **August 2023**, while this analysis was performed in **September 2026**. Spammers often use hosting IPs for a short period and then abandon them, so the IP's reputation may have been "cleaned" over time.
- Reputation databases only reflect reported activity. No reports ≠ no malicious activity.
- A legitimate OTTO newsletter would be sent from OTTO's own mail infrastructure or a reputable email service provider with valid SPF/DKIM, not from a rented VPS with a random hostname.

**Conclusion:** the IP reputation alone is inconclusive, but combined with the failed authentication, the sending infrastructure is considered **suspicious**.

---

## 5. URL Analysis

The HTML body (`Content-Transfer-Encoding: 7bit`, not encoded) was searched for `href` and `http` in the raw `.eml` file. The following URLs were extracted:

| # | URL (defanged) | Location in email | Result |
|---|----------------|-------------------|--------|
| 1 | `hxxps://t[.]co/mvSRObYnj7` | Preheader, main button "ERHALTEN SIE IHRE BESTELLUNG", text link | Link is no longer active — redirect destination could not be retrieved |
| 2 | `hxxps://t[.]co/eYVtqVunRC` | Injected inside a CSS `line-height` property (malformed) | Link is no longer active |
| 3 | `hxxp://bsq2[.]firiri[.]shop/...` | "hier" (here) link | Domain flagged as phishing (see below) |
| 4 | `hxxp://bsq2[.]firiri[.]shop/...` | "click here" unsubscribe link | Same domain |
| 5 | `hxxp://bsq2[.]firiri[.]shop/...` | Hidden 1×1 px image | Tracking pixel |
| 6 | `naintl.s3.eu-west-1.amazonaws[.]com/_CTJU/2020/2023/June/13/25345_DEATCH_KetoXplode_GummiesDiet.png` | Product image | Image hosted on Amazon S3 (abuse of legitimate cloud storage) |

**`t.co` analysis:** `t.co` is the official URL shortener of Twitter/X. The domain itself is legitimate (0/91 on VirusTotal, top-1K domain), which is exactly why attackers use it: email filters trust the domain, and the real malicious destination stays hidden. Only the full shortened URL can be judged, not the domain. Both links were inactive at the time of analysis (likely removed by Twitter/X).

**`firiri.shop` analysis (VirusTotal):**

- **12/91** vendors flagged the domain as malicious.
- **Phishing:** alphaMountain.ai, BitDefender, CyRadar, Fortinet, G-Data, Kaspersky, Lionic, Sophos, VIPRE
- **Malicious:** Chong Lua Dao, CRDF, Webroot
- **Suspicious:** ESET
- Registrar: Namecheap Inc.

---

## 6. Phishing Techniques Observed

| Technique | Evidence |
|-----------|----------|
| **Brand impersonation / spoofing** | Visible sender `newsletter.otto.de` while the real sender is `winner-win.art` (DMARC fail) |
| **Reply-To redirection** | Replies go to `reply_to@winner-win.art` instead of OTTO |
| **URL shortener abuse** | `t.co` links hide the final destination and help bypass URL filters |
| **Tracking pixel** | Invisible 1×1 px image (`width="1px"`, `visibility:hidden`) loaded from `firiri.shop`. When the email is opened, the attacker learns that the address is active and the email was read |
| **Unencrypted links** | `firiri.shop` links use `http://` instead of `https://`, so traffic is not encrypted — unusual for any legitimate company |
| **Abuse of legitimate cloud** | Product image hosted on Amazon S3 to appear trustworthy and avoid blocking |
| **Urgency & scarcity** | Preheader: stock is "running out", offer "limited to June", "Hurry up!" due to "extremely high demand" |
| **Too-good-to-be-true offer** | Claims of fast weight loss, "proven by studies", available without prescription |
| **Inconsistent content** | Image `alt` text says "DERMA 360 ANTI-AGING" while the product is a diet gummy — sign of a reused spam template |
| **Fake / unrelated address** | Footer address "616 Corporate Way, Valley Cottage, NY 10989" (USA) is not related to OTTO, which is based in Hamburg, Germany |

---

## 7. Indicators of Compromise (IOCs)

| Type | Value | Verdict |
|------|-------|---------|
| IPv4 | `80.96.157[.]91` | Suspicious — unauthorized sender (SPF softfail), no reputation hits |
| Hostname | `qktfxzqsjmwfnksijbkrjpmhgadbswa.whskk2` | Suspicious — randomly generated HELO |
| Domain | `winner-win[.]art` | Suspicious — spoofing infrastructure (not verified on TI platforms) |
| Email | `reply_to@winner-win[.]art` | Suspicious — attacker Reply-To |
| Domain | `firiri[.]shop` | **Malicious** — VirusTotal 12/91 (Phishing) |
| Domain | `bsq2[.]firiri[.]shop` | **Malicious** — link and tracking pixel host |
| URL | `hxxps://t[.]co/mvSRObYnj7` | Suspicious — inactive, destination unknown |
| URL | `hxxps://t[.]co/eYVtqVunRC` | Suspicious — inactive, destination unknown |

> Note: `t.co` and `amazonaws.com` are legitimate services and must **not** be blocked at the domain level — only the specific URLs.

---

## 8. Verdict

| | |
|---|---|
| **Classification** | Phishing / Scam (brand impersonation) |
| **Risk level** | 🔴 High |
| **Confidence** | High |

**Reasoning:** SPF, DKIM and DMARC all failed; the sender spoofed OTTO's domain; replies are redirected to an attacker domain; the email contains links to a domain flagged as phishing by 12 vendors, a hidden tracking pixel, and classic social-engineering tactics (urgency, scarcity, unrealistic promises).

---

## 9. Recommendations

1. **Block IOCs** — add `firiri.shop` and `winner-win.art` to the email gateway and web proxy blocklists; block IP `80.96.157.91` on the email gateway. Block only the specific `t.co` URLs, not the whole domain.
2. **Search & Purge** — search all mailboxes (e.g. Microsoft 365 / Exchange) for emails with the same sender, Reply-To or subject and remove them.
3. **Check for user interaction** — review proxy, DNS and firewall logs in the SIEM for any connections to `firiri.shop` or the `t.co` URLs, to find users who clicked.
4. **Respond to affected users** — if a user clicked and entered data, reset their credentials, check for suspicious logins and open an incident ticket.
5. **Improve detection** — create an email gateway rule that flags or quarantines messages where DMARC fails for well-known brand domains, or where the From and Reply-To domains do not match.
6. **User awareness** — share this example with employees as a phishing awareness case: check the real sender, do not trust urgency, and report suspicious emails to the SOC.

---

## 10. Tools Used

- **GitHub Raw view** — reading email headers and HTML body
- **VirusTotal** — IP, domain and URL reputation
- **AbuseIPDB** — IP abuse reports and ISP information
- **URLScan.io** — URL redirect analysis
- **Browser search (Ctrl/Cmd + F)** — extracting URLs from the raw email
