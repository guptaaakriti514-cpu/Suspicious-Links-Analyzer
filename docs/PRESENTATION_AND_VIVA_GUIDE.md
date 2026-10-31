# MailShield Academic Presentation & Viva Defense Guide

This guide is prepared for an **MCA Cybersecurity Final Project Presentation & External Viva Defense**. It details the demonstration workflow, technical justifications, and anticipated examiner questions with high-scoring answers.

---

## 1. 5-Minute Demonstration Script for Examiners

### Step 1: Launch & SOC Dashboard (Screen 1)
- **Action:** Launch the application.
- **Talking Point:** *"Good morning/afternoon respected examiners. Today I present **MAILSHIELD**, an advanced email threat detection, investigation, and digital forensics desktop platform engineered in Java 21 for SOC operations. Upon launching, our Overview Dashboard visualizes live telemetry from an embedded, tamper-evident SQLite database, displaying analyzed messages, active cases, and cloud inbox connector states."*

### Step 2: One-Click Offline Viva Demonstration (Screen 2)
- **Action:** Click **2. Analyze Email** in the sidebar.
- **Scenario A (Credential Phishing):** Select `DEMO-01: Critical Credential Harvesting Phish (PayPal Impersonation)` and click **Load Scenario**.
- **Talking Point:** *"Notice the multi-layered attack:
  1. The From display name says 'PayPal Security Support' but envelope From is `paypa1-account-security.net` (an algorithmic typosquat).
  2. The visible anchor text reads `https://www.paypal.com/security/verify-account`, but the true destination routes to a raw IP host: `http://198.51.100.55/login/verify-identity.php`.
  3. Header authentication parsing confirms SPF=FAIL, DKIM=FAIL, and DMARC=FAIL.
  4. Our deterministic scoring engine caps correlated social engineering penalties while evaluating the attack as a **CRITICAL THREAT (Score 82+/100)** with 94% confidence."*
- **Scenario B (Business Email Compromise):** Select `DEMO-02: High-Risk CEO Fraud / BEC` and click **Load Scenario**.
- **Talking Point:** *"This showcases a text-only Business Email Compromise attack with no attachments or links. The sender impersonates the CEO requesting a confidential $78,500 wire transfer with strict urgency and secrecy demands. MailShield identifies the Reply-To pointing to an external Gmail address and flags the financial extortion/wire patterns as **HIGH RISK**."*
- **Scenario C (Malicious Attachment):** Select `DEMO-03: Malicious Attachment (Double Extension)` and click **Load Scenario**.
- **Talking Point:** *"Here an overdue invoice lure carries `Invoice_Sept2026_Final.pdf.exe`. MailShield inspects attachment metadata without executing binaries, detects the disguised double extension designed to bypass Windows default extension hiding, and triggers an immediate **CRITICAL QUARANTINE** finding."*

### Step 3: Forensic Chain of Custody & Evidence (Screen 8)
- **Action:** Navigate to **8. Evidence & Reports**.
- **Talking Point:** *"Digital forensics requires cryptographic integrity. Notice that immediately upon ingestion, MailShield computes a SHA-256 message digest over the raw RFC 5322 bytes and records it in an append-oriented custody log. We can copy the hash with one click or export a secure, XSS-hardened HTML forensic investigation report."*

### Step 4: Standalone URL Forensics (Screen 5)
- **Action:** Navigate to **5. URL & Domain Forensics**.
- **Talking Point:** *"Analysts often receive suspicious links reported by users. Our URL inspector allows safe inspection of IP hosts, homoglyphs, and anchor mismatches without ever making network calls or following redirects."*

---

## 2. Likely Examiner Viva Questions & Model Answers

### Q1: Why did you choose Java Swing with FlatLaf instead of JavaFX or a web stack?
**Model Answer:**
> *"Starting with Java 11, JavaFX was decoupled from the OpenJDK. Running JavaFX in modern JDK 21 environments requires platform-specific native libraries, explicit module-path VM flags, or external SDK downloads that make execution brittle for security operators and beginner deployment. Java Swing is 100% native standard Java bundled in JDK 21, guaranteeing instant execution with zero external runtime configurations. Paired with FlatLaf, we achieved a modern, responsive, high-contrast Dark SOC theme with zero compromise on visual polish."*

### Q2: Why parse SPF, DKIM, and DMARC from email headers instead of doing live DNS lookups?
**Model Answer:**
> *"In forensic investigation, imported `.eml` files or historical incident messages represent state at the time of transmission. Performing live DNS queries on the investigator's workstation introduces two major flaws:
> 1. It queries the current DNS records rather than the records that existed when the attacker sent the message (historical inaccuracy).
> 2. It leaks confidential client information or alerts the adversary that their domain is under investigation.
> MailShield parses the authentic receiving MTA's `Authentication-Results` header while making it clear to the analyst that text headers alone are historical parsed evidence, not live cryptographic proof."*

### Q3: How do you prevent attackers from exploiting MailShield via malicious email payloads?
**Model Answer:**
> *"We follow strict Security-by-Design principles:
> 1. Attachments are never automatically unpacked or executed; only metadata, extensions, and byte SHA-256 hashes are analyzed.
> 2. Email HTML is processed through JSoup's safe DOM tree, stripping active scripts and event handlers.
> 3. Hyperlinks are parsed statically via `java.net.URI` without following redirects or pinging external servers.
> 4. In generated reports, all untrusted inputs (headers, subjects, snippets) are strictly sanitized using HTML entity escaping (`&lt;script&gt;`) to prevent Cross-Site Scripting (XSS)."*

### Q4: How does your risk scoring engine handle conflicting indicators?
**Model Answer:**
> *"Our `DefaultRiskScoringEngine` uses Category Ceiling Caps. For example, Social Engineering findings are capped at 30 points. This prevents an email with 5 similar urgency phrases from having its score artificially inflated from Low to Critical. Conversely, lethal threat indicators like disguised executable payloads or bare IP destination targets immediately elevate the baseline score to Critical (80+)."*

### Q5: How do the Gmail and Outlook integrations work without storing user passwords?
**Model Answer:**
> *"Both integrations utilize modern, industry-standard delegated OAuth 2.0 authorization flows (Google OAuth2 PKCE and Microsoft Entra ID). The application never asks for or stores user passwords. Tokens are stored in a local obfuscated vault with minimal read-only scopes (`gmail.readonly` and `Mail.Read`). Furthermore, unconfigured integrations are truthfully reported as Disconnected or Not Configured rather than fabricating fake connections."*

---

## 3. Known Limitations & Future Enhancements

| Area | Current Implementation | Planned Future Enhancement |
|---|---|---|
| **Malware Analysis** | Static metadata, double-extension detection, hash checking | Integration with isolated Cuckoo / Any.Run sandbox API |
| **Inbox Synchronization** | Mode A: On-demand sync; Mode B: Configurable background polling | Push notifications via Gmail Push / Microsoft Graph Webhooks |
| **Threat Intelligence** | Curated local offline SOC fixtures + optional VirusTotal | TAXII / STIX 2.1 automated threat feed synchronization |
| **Evidence Storage** | Local SQLite repository with SHA-256 chain of custody | Hardware Security Module (HSM) or PKI timestamp token signing |

