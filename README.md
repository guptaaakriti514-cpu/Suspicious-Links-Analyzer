# MAILSHIELD &mdash; Advanced Email Threat Detection, Investigation & Digital Forensics Platform

[![Java Version](https://img.shields.io/badge/Java-21%20LTS-007396?logo=openjdk&logoColor=white)](https://adoptium.net/)
[![Build Tool](https://img.shields.io/badge/Maven-3.9.6-C71A36?logo=apachemaven&logoColor=white)](https://maven.apache.org/)
[![UI Framework](https://img.shields.io/badge/UI-Swing%20%2B%20FlatLaf%20Dark%20SOC-1e293b)](https://www.formdev.com/flatlaf/)
[![Database](https://img.shields.io/badge/Storage-SQLite%20Embedded-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Tests](https://img.shields.io/badge/Tests-33%20Passed%20%28100%25%29-10b981)](https://junit.org/junit5/)
[![Security](https://img.shields.io/badge/Forensics-SHA--256%20Custody%20Trail-38bdf8)](docs/ARCHITECTURE_AND_DETECTION.md)

**MailShield** is a complete, production-grade cybersecurity desktop platform inspired by enterprise Security Operations Center (SOC) workflows and digital forensics requirements. Engineered as an MCA Cybersecurity academic project, it bridges the gap between raw RFC 5322 email transmission protocols and explainable indicator triage.

> 📘 **Looking for the complete manual?** Check out the comprehensive [Step-by-Step Operator Manual](docs/STEP_BY_STEP_MANUAL.md) for full setup, inbox sync, and examiner viva preparation.

---

## Key Highlights & Architectural Strengths

- **No Complex VM Flags in Eclipse:** Built with native Java 21 Swing and **FlatLaf 3.5.1**, delivering a high-contrast Dark SOC operations interface that runs out-of-the-box in Eclipse via simple `Run As -> Java Application` (no `--module-path` or missing native JavaFX library errors).
- **10 Dedicated SOC Navigation Screens:**
  1. *Overview Dashboard* (persisted telemetry, incident counts, connector states)
  2. *Analyze Email* (raw text paste, .eml import, 1-click viva scenarios, findings breakdown)
  3. *Connected Inboxes* (Google Gmail API v1 & Microsoft Outlook Graph API)
  4. *Email Investigation Queue* (search, triage, filter by risk level)
  5. *URL & Domain Forensics* (deceptive anchor mismatches, IP hostnames, homoglyphs)
  6. *Investigation Cases* (case lifecycle, analyst notes, status progression)
  7. *Threat Intelligence* (IOC reputation feeds, curated indicators)
  8. *Evidence & Reports* (SHA-256 chain of custody, XSS-hardened HTML report export)
  9. *Settings & Security* (vault status, SQLite paths, OAuth credentials, token purge)
  10. *Academic Viva Guide* (threat model, architecture, examiner Q&A)
- **Safe Static Analysis (Zero Detonation):** Never unpacks or executes malicious binaries. Traverses MIME structures safely, strips active scripts via JSoup DOM sanitization, and statically parses hyperlinks.
- **Explainable Risk Scoring:** Features strict **Category Ceiling Caps** preventing indicator multi-counting and false positive score inflation.
- **Forensic Chain of Custody:** Calculates SHA-256 digests over original raw bytes upon ingestion and logs immutable custody records in an ACID SQLite database (`data/mailshield.db`).
- **Complete Offline Viva Demo Mode:** Includes 4 realistic synthetic cyberattack scenarios (Credential Phishing, CEO Fraud / BEC, Disguised Double Extension, Benign Newsletter) that work 100% offline with zero internet access or cloud credentials.

---

## Quick Start Guide (Windows + JDK 21 + Eclipse)

### Prerequisites
- **Operating System:** Windows 10 or 11
- **Java Development Kit:** JDK 21 LTS (e.g. Eclipse Adoptium Temurin 21)
- **IDE:** Eclipse IDE for Java Developers (2023 or newer)

---

### Step-by-Step Eclipse Setup (Beginner Friendly)

1. **Open Eclipse:** Launch Eclipse and choose your workspace.
2. **Import the Project:**
   - Click **File** &rarr; **Import...**
   - In the import dialog, expand the **Maven** folder and select **Existing Maven Projects**.
   - Click **Next >**.
   - For **Root Directory**, click **Browse...** and select:
     ```
     C:\Users\hp\Desktop\java pro
     ```
   - Ensure the checkbox next to `/pom.xml` is checked.
   - Click **Finish**.
3. **Wait for Maven Build:** Eclipse will automatically read `pom.xml` and download dependencies into your local Maven cache.
4. **Run the Application:**
   - In Eclipse's **Package Explorer**, expand:
     `src/main/java` &rarr; `com.mailshield.app` &rarr; right-click `MailShieldApplication.java`.
   - Select **Run As** &rarr; **Java Application**.
   - *The MailShield SOC Desktop application will launch immediately!*

---

### Running via Command Line (PowerShell)

You can also build, test, and run the platform directly from PowerShell using the included Maven Wrapper (`mvnw.cmd`):

```powershell
# 1. Run all 33 automated JUnit 5 tests
.\mvnw.cmd test

# 2. Package standalone JAR
.\mvnw.cmd package -DskipTests

# 3. Launch the desktop GUI
.\mvnw.cmd compile exec:java
```

---

## 4 Built-in Academic Viva Demo Scenarios

In Screen 2 (**Analyze Email**), open the **Viva Demo Scenarios** dropdown at the top right and click **Load Scenario**:

1. **`DEMO-01: Critical Credential Harvesting Phish (PayPal Impersonation)`**
   - *Attack Vector:* Urgent account suspension deadline ("within 24 hours"), deceptive typosquat domain (`paypa1-account-security.net`), visible anchor text (`paypal.com`) routing to a bare IP host (`198.51.100.55`), and SPF/DKIM/DMARC authentication failures.
   - *Expected Verdict:* **CRITICAL THREAT (Score 82+/100)**.
2. **`DEMO-02: High-Risk CEO Fraud / BEC (Business Email Compromise)`**
   - *Attack Vector:* Text-only social engineering lure impersonating company CEO requesting an urgent $78,500 outbound wire transfer with strict confidentiality/NDA demands, with `Reply-To` directed to an external Gmail address.
   - *Expected Verdict:* **HIGH RISK (Score 60+/100)**.
3. **`DEMO-03: Malicious Attachment (Double Extension .pdf.exe)`**
   - *Attack Vector:* Fake overdue remittance lure containing `Invoice_Sept2026_Final.pdf.exe` designed to exploit Windows default file extension hiding.
   - *Expected Verdict:* **CRITICAL THREAT (Score 82+/100)**.
4. **`DEMO-04: Benign Legitimate Email (GitHub Security Lab)`**
   - *Attack Vector:* Authentic engineering newsletter with valid SPF/DKIM/DMARC pass, matching HTTPS links, and no psychological pressure.
   - *Expected Verdict:* **LOW RISK (Score 0-15/100)**.

---

## Package Structure

```
com.mailshield
├── app
│   ├── MailShieldApplication.java     # Bootstrap & dependency injection
│   └── DemoDataFixtures.java          # Deterministic offline viva scenarios
├── config
│   └── AppConfig.java                 # Configuration (.env & system variables)
├── detection
│   ├── DetectionEngine.java           # Master analysis pipeline coordinator
│   ├── HeaderAnalyzer.java / SafeHeaderAnalyzer.java
│   ├── ContentAnalyzer.java / SafeContentAnalyzer.java
│   ├── UrlAnalyzer.java / SafeUrlAnalyzer.java
│   ├── AttachmentMetadataAnalyzer.java / SafeAttachmentAnalyzer.java
│   └── AuthenticationResultAnalyzer.java
├── forensics
│   ├── EvidenceManager.java           # Cryptographic SHA-256 custody trail
│   └── DefaultEvidenceManager.java
├── ingestion
│   ├── EmailParser.java               # RFC 5322 & .eml parsing contract
│   └── SafeEmailParser.java           # Jakarta Mail 2.1 streaming parser
├── intelligence
│   ├── ThreatIntelligenceService.java
│   └── LocalThreatIntelligenceService.java # Offline curated IOC threat database
├── model
│   ├── EmailMessage.java              # Normalized immutable email domain model
│   ├── EmailHeader.java, EmailAttachmentMetadata.java, ExtractedUrl.java
│   ├── Finding.java, RiskAssessment.java, AnalysisResult.java
│   ├── InvestigationCase.java, EvidenceRecord.java
│   └── Enums: Severity, RiskLevel, CaseStatus, CasePriority, ProviderType
├── monitoring
│   ├── MonitoringService.java         # Synchronization & polling contract
│   └── DefaultMonitoringService.java  # Thread-isolated scheduler with pause/resume
├── providers
│   ├── EmailProvider.java             # Common provider interface
│   ├── GmailProvider.java / GoogleGmailProvider.java   # Official Google OAuth2 PKCE
│   └── OutlookProvider.java / MicrosoftOutlookProvider.java # Official MSAL Graph API
├── reporting
│   ├── ReportGenerator.java           # Report generation contract
│   └── HtmlReportGenerator.java       # XSS-hardened SOC HTML report & CSV exporter
├── scoring
│   ├── RiskScoringEngine.java         # Scoring engine contract
│   └── DefaultRiskScoringEngine.java  # Explainable category ceiling engine
├── security
│   ├── CredentialStore.java           # Vault contract
│   └── DefaultCredentialStore.java    # Local obfuscated token store
├── storage
│   ├── CaseRepository.java            # SQLite storage contract
│   └── SqliteCaseRepository.java      # Parameterized SQLite persistence & checkpoints
├── ui
│   ├── MailShieldMainWindow.java      # Main desktop window & sidebar navigation
│   ├── UiTheme.java                   # FlatLaf Dark SOC theme styling constants
│   ├── DashboardPanel.java            # Screen 1: Overview Dashboard
│   ├── AnalyzeEmailPanel.java         # Screen 2: Deep Email Threat Analysis
│   ├── ConnectedInboxesPanel.java     # Screen 3: Connected Inboxes (Gmail/Outlook)
│   ├── InvestigationQueuePanel.java   # Screen 4: Investigation Queue
│   ├── UrlDomainAnalysisPanel.java    # Screen 5: URL Forensics Inspector
│   ├── CasesPanel.java                # Screen 6: Incident Case Management
│   ├── ThreatIntelligencePanel.java   # Screen 7: Threat Intelligence & IOC Lookup
│   ├── EvidenceReportsPanel.java      # Screen 8: Forensics Evidence & Reports
│   ├── SettingsSecurityPanel.java     # Screen 9: Settings & Credentials
│   └── AboutHelpPanel.java            # Screen 10: Academic Documentation & Viva Q&A
└── util
    └── SecurityUtils.java             # Cryptographic hashing & HTML escaping
```

---

## Detailed Documentation Directory

For complete setup guides and academic evaluation materials, please consult:

- 📖 [Google Cloud / Gmail API OAuth Setup Guide](docs/GOOGLE_GMAIL_SETUP.md)
- 📖 [Microsoft Entra / Outlook 365 Setup Guide](docs/MICROSOFT_OUTLOOK_SETUP.md)
- 📊 [Architecture, Ingestion & Detection Engine Specifications](docs/ARCHITECTURE_AND_DETECTION.md)
- 🎓 [Academic Presentation & Viva Defense Guide](docs/PRESENTATION_AND_VIVA_GUIDE.md)
- 📋 [Feature Delivery & Verification Matrix](docs/FEATURE_MATRIX.md)

---

## Verification & Test Results

The platform includes **33 comprehensive automated unit & integration tests** covering all modules:

```powershell
[INFO] Running com.mailshield.detection.DetectionEnginePipelineTest (4 tests) - PASS
[INFO] Running com.mailshield.detection.SafeAttachmentAnalyzerTest  (4 tests) - PASS
[INFO] Running com.mailshield.detection.SafeContentAnalyzerTest     (3 tests) - PASS
[INFO] Running com.mailshield.detection.SafeHeaderAnalyzerTest      (4 tests) - PASS
[INFO] Running com.mailshield.detection.SafeUrlAnalyzerTest         (6 tests) - PASS
[INFO] Running com.mailshield.ingestion.SafeEmailParserTest         (3 tests) - PASS
[INFO] Running com.mailshield.reporting.HtmlReportGeneratorTest     (2 tests) - PASS
[INFO] Running com.mailshield.scoring.DefaultRiskScoringEngineTest (4 tests) - PASS
[INFO] Running com.mailshield.storage.SqliteCaseRepositoryTest     (3 tests) - PASS
[INFO] -------------------------------------------------------
[INFO] Results: 33 Tests run, 0 Failures, 0 Errors, 0 Skipped
[INFO] BUILD SUCCESS
```

---

## Security & Ethical Disclaimer

MailShield is designed strictly for authorized cybersecurity incident triage, defensive email threat identification, digital forensics preservation, and academic research. The system acts as a decision-support assistant and does not guarantee the detection of 100% of advanced persistent threats (APTs). Never download or execute unverified email attachments in production environments.

