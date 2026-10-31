# MailShield — Complete Step-by-Step Operator & Developer Manual

> **Product**: MailShield — Advanced Email Threat Detection, Investigation & Digital Forensics Platform  
> **Target Audience**: Students, MCA Examiners, SOC Analysts, and Java Developers  
> **Platform Requirements**: Windows 10/11, JDK 21 LTS, Eclipse IDE / CLI  

---

## Table of Contents
1. [Overview & Project Philosophy](#1-overview--project-philosophy)
2. [Prerequisites & System Setup](#2-prerequisites--system-setup)
3. [Opening & Running in Eclipse IDE](#3-opening--opening-and-running-in-eclipse-ide)
4. [Running via Terminal / PowerShell](#4-running-via-terminal--powershell)
5. [User Guide: Navigating MailShield](#5-user-guide-navigating-mailshield)
   - [5.1 SOC Operations Dashboard](#51-soc-operations-dashboard)
   - [5.2 Analyzing an Email (Paste & .EML Import)](#52-analyzing-an-email-paste--eml-import)
   - [5.3 Connecting Google Gmail (Live OAuth 2.0)](#53-connecting-google-gmail-live-oauth-20)
   - [5.4 Connecting Microsoft Outlook / Office 365 (MSAL & Graph API)](#54-connecting-microsoft-outlook--office-365-msal--graph-api)
   - [5.5 Inbox Monitoring & Auto-Inspection](#55-inbox-monitoring--auto-inspection)
   - [5.6 Case Management & Chain-of-Custody](#56-case-management--chain-of-custody)
   - [5.7 URL & Domain Threat Forensics](#57-url--domain-threat-forensics)
   - [5.8 Threat Intelligence Feeds](#58-threat-intelligence-feeds)
   - [5.9 Generating Forensic Reports](#59-generating-forensic-reports)
6. [Zero-Mock Architecture: How Real Data Flows](#6-zero-mock-architecture-how-real-data-flows)
7. [What to Add to Make This a Perfect Production Tool](#7-what-to-add-to-make-this-a-perfect-production-tool)
8. [Examiner Viva Q&A Cheat Sheet](#8-examiner-viva-qa-cheat-sheet)

---

## 1. Overview & Project Philosophy

MailShield is an enterprise-grade desktop cybersecurity platform built using **Java 21 LTS** and **Java Swing (FlatLaf SOC Dark Theme)**. It serves as an analyst workbench for:
- Detecting **Phishing**, **Business Email Compromise (BEC)**, **Spoofing**, and **Malicious Attachments**.
- Ingesting raw RFC 5322 email bodies and `.eml` files.
- Connecting to live mailboxes via **Google Gmail API** and **Microsoft Graph API**.
- Maintaining forensic evidence chains and tamper-evident cryptographic hashes (SHA-256).
- Exporting audit-ready HTML digital forensics reports.

**Zero-Mock Policy**: MailShield does not inject fake threats into your database. The SQLite repository (`data/mailshield.db`) begins empty and populates exclusively when you analyze real messages or sync inboxes.

---

## 2. Prerequisites & System Setup

Before launching MailShield, ensure your workstation meets these specifications:

| Requirement | Recommended Version | Verification Command |
|---|---|---|
| **Operating System** | Windows 10 / 11 64-bit | `winver` |
| **Java Development Kit** | Eclipse Temurin JDK 21 LTS | `java -version` |
| **Build System** | Maven 3.9+ (Wrapper included via `mvnw.cmd`) | `.\mvnw.cmd -v` |
| **IDE** | Eclipse IDE for Java Developers (2024-03 or newer) | — |

### Verifying JDK 21 in PowerShell:
```powershell
java -version
```
Expected output:
```text
openjdk version "21.0.x" ...
OpenJDK Runtime Environment Temurin-21...
```

---

## 3. Opening and Running in Eclipse IDE

MailShield uses standard Maven packaging. No complex JavaFX VM flags or `--module-path` parameters are required.

### Step 1: Open Eclipse
Launch your Eclipse IDE workspace.

### Step 2: Import as Existing Maven Project
1. Go to **File** → **Import...**
2. In the Import wizard, expand **Maven** and select **Existing Maven Projects**.
3. Click **Next**.
4. In **Root Directory**, click **Browse...** and select the project directory:  
   `c:\Users\hp\Desktop\java pro`
5. Ensure `pom.xml` is checked in the Projects list.
6. Click **Finish**. Eclipse will resolve dependencies automatically using Maven Central.

### Step 3: Run the Application
1. In the **Package Explorer**, expand:  
   `src/main/java` → `com.mailshield.app`
2. Right-click on **`MailShieldApplication.java`**.
3. Select **Run As** → **Java Application**.
4. The MailShield SOC Dark window will immediately launch on your screen.

---

## 4. Running via Terminal / PowerShell

You can build, test, and run MailShield directly from the command line using the included Maven wrapper `mvnw.cmd`.

### Run All Unit Tests (33 Automated Security Tests):
```powershell
cd "c:\Users\hp\Desktop\java pro"
.\mvnw.cmd test
```

### Build Executable JAR:
```powershell
.\mvnw.cmd package -DskipTests
```
The compiled artifact is generated at: `target/mailshield-platform-1.0.0.jar`.

### Launch the Desktop GUI:
```powershell
.\mvnw.cmd compile exec:java
```

---

## 5. User Guide: Navigating MailShield

MailShield features a left sidebar with 10 dedicated SOC functional modules.

### 5.1 SOC Operations Dashboard
- Provides high-level metrics: **Total Analyzed**, **Critical Findings**, **Active Cases**, and **Monitoring Status**.
- Displays recent email analyses with color-coded severity badges.
- Starts completely clean (0 metrics) until real data is ingested.

### 5.2 Analyzing an Email (Paste & .EML Import)
1. Click **Analyze Email** in the sidebar.
2. You have three flexible options:
   - **Option A (Manual Paste)**: Paste any raw email (including RFC 5322 headers) directly into the left text area.
   - **Option B (Import .EML)**: Click **Import .EML File** to open any email exported from Thunderbird, Outlook, or Apple Mail.
   - **Option C (Academic Training Scenarios)**: Select a scenario from the top-right dropdown (e.g., *Credential Harvesting Phish* or *CEO Fraud Wire Request*) and click **Load Scenario**.
3. Click **⚡ Run Threat & Forensic Analysis**.
4. Review the real-time breakdown:
   - **Explainable Threat Score (0–100)** and Risk Rating (Clean, Low, Medium, High, Critical).
   - **Authentication Results**: SPF, DKIM, and DMARC verification statuses.
   - **Detected Security Findings**: Specific rule violations with severity, confidence, and recommended remediation.
   - **Extracted Hyperlinks**: Flags suspicious TLDs, IP hosts, and anchor-text mismatches.
5. Click **💾 Save as Incident Case** to store the finding in the forensic repository, or **📄 Generate Report** to export an audit report.

### 5.3 Connecting Google Gmail (Live In-GUI OAuth 2.0)
You do NOT need to manually edit any `.env` or program files. You can configure everything directly inside MailShield:
1. Open MailShield and click **3. Connected Inboxes** in the sidebar.
2. In the **Google Gmail API** card, click **⚙ Configure**.
3. A configuration dialog opens:
   - Paste your **Google Client ID** (e.g. `441236...apps.googleusercontent.com`).
   - Paste your **Google Client Secret** (e.g. `GOCSPX-...`).
   - Leave the Redirect Port as `8888` (or custom).
4. Click **Save & Apply Credentials**. A confirmation popup will confirm that the credentials were saved to `.env` and applied to your running session.
5. In the Gmail card, the badge will now show `Credentials: ✓ Configured in GUI`.
6. Click **Connect Gmail**:
   - A dialog will notify you that MailShield is waiting for Google sign-in.
   - Your default web browser will open to Google's official OAuth consent screen.
   - Sign in with your Google Account and click **Continue / Allow**.
   - Upon completion, MailShield shows a confirmation dialog:
     `✓ Google Gmail Connected Successfully! Authorized Mailbox: your.name@gmail.com`.
7. Click **Sync (10 Msgs)** to pull recent unread emails directly into the investigation queue for automated threat analysis.

### 5.4 Connecting Microsoft Outlook / Office 365 (MSAL & Graph API)
To inspect your actual Microsoft Outlook inbox without touching program files:
1. In MailShield, navigate to **3. Connected Inboxes**.
2. In the **Microsoft Outlook / 365** card, click **⚙ Configure**.
3. Paste your Microsoft Entra **Application (Client) ID** and **Directory (Tenant) ID** (or leave `common` for personal Outlook/Hotmail).
4. Click **Save & Apply Credentials**.
5. Click **Connect Outlook**.
6. Follow the authentication prompt (Device Code or Browser Sign-In).
7. Once connected, click **Sync (10 Msgs)** to ingest recent inbox items.

### 5.5 Inbox Monitoring & Auto-Inspection
1. Go to **Connected Inboxes** or **Settings & Security**.
2. Configure the polling frequency (e.g., every 60 seconds).
3. Toggle **Start Automated Monitoring**.
4. MailShield runs in the background, checking connected providers for newly arriving emails, automatically executing the multi-layer detection pipeline, and raising alerts for High/Critical risks.

### 5.6 Case Management & Chain-of-Custody
1. Click **Investigation Cases** in the sidebar.
2. View all tracked incidents with priority, status (`OPEN`, `UNDER_INVESTIGATION`, `RESOLVED`), and assigned analyst.
3. Select any case to update analyst notes, escalate priority, or close the investigation.
4. Every piece of evidence records:
   - Exact UTC timestamp.
   - Cryptographic SHA-256 hash of original raw bytes.
   - Forensic chain-of-custody log.

### 5.7 URL & Domain Threat Forensics
1. Click **URL & Domain Analysis**.
2. Paste any suspicious link or domain name (e.g., `http://198.51.100.55/login/verify.php`).
3. MailShield checks:
   - IP address host representation.
   - Risky/abused Top-Level Domains (`.top`, `.xyz`, `.work`, `.ru`, `.cc`).
   - Homograph/typosquatting spoofing markers (`paypa1`, `micros0ft`).
   - Suspicious path heuristics (`/login/`, `update-account`).

### 5.8 Threat Intelligence Feeds
1. Click **Threat Intelligence**.
2. Query any Domain, Host IP, or SHA-256 hash.
3. The platform correlates the indicator against active reputation feeds and records an audit log in the lookup telemetry table.

### 5.9 Generating Forensic Reports
1. In **Evidence & Reports** or from an active analysis in **Analyze Email**, click **Generate HTML Forensic Report**.
2. MailShield exports an audit-ready, tamper-evident HTML report featuring:
   - Case metadata & analyst details.
   - Cryptographic SHA-256 hash of original email bytes.
   - Sanitized header table (safe from XSS).
   - Findings summary categorized by MITRE ATT&CK / SOC heuristics.
   - Disclaimers separating observed facts from heuristic conclusions.

---

## 6. Zero-Mock Architecture: How Real Data Flows

```
[Raw RFC 5322 / .EML / Gmail / Graph API]
                     │
                     ▼
         [SafeEmailParser (MimeMessage)]
                     │
                     ▼
           [EmailMessage (Normalized)]
                     │
                     ├──────────────────────────┐
                     ▼                          ▼
         [Detection Engine Pipeline]     [SHA-256 Evidence Hashing]
         ├── SafeHeaderAnalyzer                 │
         ├── SafeContentAnalyzer                ▼
         ├── SafeUrlAnalyzer             [DefaultEvidenceManager]
         ├── SafeAttachmentAnalyzer             │
         ├── LocalThreatIntelligenceService     ▼
         └── DefaultRiskScoringEngine     [data/mailshield.db (SQLite)]
                     │
                     ▼
          [AnalysisResult & Findings]
                     │
                     ▼
         [MailShield Desktop GUI & HTML Reports]
```

---

## 7. What to Add to Make This a Perfect Production Tool

To elevate MailShield from an MCA academic project to an enterprise production-grade tool, here are recommended enhancements:

### 1. Live VirusTotal v3 REST API Integration
- **Current State**: `LocalThreatIntelligenceService` operates as a curated offline threat database.
- **Enhancement**: Integrate an asynchronous HTTP client to query VirusTotal v3 (`/api/v3/urls`, `/api/v3/files/{id}`) and AbuseIPDB when an API key is saved in `Settings & Security`.

### 2. Native PDF Report Export
- **Current State**: Tamper-evident HTML reports with modern responsive CSS.
- **Enhancement**: Add `openpdf` or `iText7` Maven dependencies to generate digitally signed PDF investigation dossiers with embedded screenshots.

### 3. Externalized YARA & Sigma Rule Engine
- **Current State**: Regex heuristics are hardcoded in Java analyzers for maximum compilation safety.
- **Enhancement**: Allow security teams to write detection rules in YAML/JSON (e.g., `rules/phishing_rules.json`) so new threat patterns can be added without recompiling the Java code.

### 4. DMARC Aggregate (RUA/RUF) Report Ingestion
- **Enhancement**: Provide a parser for `.xml.gz` DMARC aggregate reports received by enterprise domain administrators to visualize organizational spoofing trends.

### 5. Windows System Tray Notifications
- **Enhancement**: Implement `java.awt.SystemTray` so background monitoring displays native desktop toast notifications whenever a Critical threat arrives.

---

## 8. Examiner Viva Q&A Cheat Sheet

**Q1: Why did you choose Java Swing over JavaFX?**  
*Answer*: Java Swing with FlatLaf allows cross-platform native dark rendering without requiring external JRE modularity arguments (`--module-path`), making the application lightweight, standalone, and compatible with any standard JDK 21 installation.

**Q2: How do you prevent malicious email content from harming the analyst?**  
*Answer*: We follow a strict zero-trust ingestion model. Email HTML is never rendered in an active browser component. Links are deactivated, scripts are stripped, attachments are hashed without execution, and HTML reports escape all user-supplied headers.

**Q3: How does your risk scoring engine prevent false positives?**  
*Answer*: We use a multi-factor weighted scoring algorithm (`DefaultRiskScoringEngine`) where points decay or compound based on confidence levels. For instance, Return-Path differences alone produce a low-severity informational flag, whereas combined SPF failure and anchor-text mismatch escalate the score to Critical.

**Q4: Is the database pre-seeded with fake threats?**  
*Answer*: No. The database follows a zero-mock policy. It starts completely empty, storing only real emails parsed or synchronized during the session.

