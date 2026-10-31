# MailShield Architecture, Ingestion & Detection Engine Specifications

## 1. System Architecture Overview

MailShield is structured according to clean layered architecture principles, ensuring strict separation of presentation (Swing/FlatLaf), domain modeling, ingestion adapters, detection heuristics, and persistence.

```mermaid
flowchart TD
    subgraph UI ["Desktop Presentation Layer (FlatLaf SOC Dark)"]
        DASH[Overview Dashboard]
        ANALYZE[Analyze Email Screen]
        INBOX[Connected Inboxes]
        QUEUE[Investigation Queue]
        URLS[URL Forensics Inspector]
        CASES[Incident Cases]
        INTEL[Threat Intelligence]
        REPORTS[Evidence & Reports]
        SETTINGS[Settings & Security]
    end

    subgraph INGESTION ["Ingestion & Normalization Layer"]
        PASTE[Manual Paste]
        EML[RFC 5322 .EML Stream]
        GMAIL[Google Gmail API v1]
        OUTLOOK[Microsoft Graph API]
        FIXTURE[Offline Viva Fixtures]
        PARSER[SafeEmailParser - Jakarta Mail 2.1]
    end

    subgraph DETECTION ["Detection & Scoring Engine"]
        HDR[SafeHeaderAnalyzer]
        CONTENT[SafeContentAnalyzer]
        URL_DET[SafeUrlAnalyzer]
        ATT_DET[SafeAttachmentAnalyzer]
        AUTH_DET[AuthenticationResultAnalyzer]
        INTEL_SVC[LocalThreatIntelligenceService]
        SCORE_ENG[DefaultRiskScoringEngine]
    end

    subgraph PERSISTENCE ["Forensics & Local Persistence Layer"]
        SQLITE[(SQLite Embedded DB: mailshield.db)]
        EVD_MGR[EvidenceManager - SHA-256 Hashing]
        CASE_REPO[SqliteCaseRepository]
        VAULT[Secured Credential Vault]
        RPT_GEN[HtmlReportGenerator - XSS Hardened]
    end

    PASTE --> PARSER
    EML --> PARSER
    GMAIL --> PARSER
    OUTLOOK --> PARSER
    FIXTURE --> PARSER

    PARSER --> |EmailMessage Domain Model| DETECTION
    DETECTION --> |AnalysisResult & Findings| EVD_MGR
    EVD_MGR --> CASE_REPO
    CASE_REPO --> SQLITE
    CASE_REPO --> UI
    RPT_GEN --> UI
```

---

## 2. Detection Pipeline Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as SOC Analyst
    participant UI as MailShield Desktop UI
    participant Parser as SafeEmailParser
    participant Engine as DetectionEngine
    participant Scorer as DefaultRiskScoringEngine
    participant Evd as EvidenceManager
    participant DB as SqliteCaseRepository

    Analyst->>UI: Pastes Email or Imports .EML File
    UI->>Parser: parseRawText() / parseEmlStream()
    Parser->>Parser: Parse MIME parts & compute raw SHA-256
    Parser-->>UI: EmailMessage (Immutable Domain Model)
    UI->>Engine: analyzeEmail(EmailMessage)
    par Parallel Sub-Analyzers
        Engine->>Engine: SafeHeaderAnalyzer.analyzeHeaders()
        Engine->>Engine: SafeContentAnalyzer.analyzeContent()
        Engine->>Engine: SafeUrlAnalyzer.analyzeUrls()
        Engine->>Engine: SafeAttachmentAnalyzer.analyzeAttachments()
        Engine->>Engine: LocalThreatIntelligenceService.checkReputation()
    end
    Engine->>Engine: Deduplicate Findings by Rule & Snippet
    Engine->>Scorer: evaluateRisk(message, uniqueFindings)
    Scorer->>Scorer: Apply category ceiling caps & evaluate score
    Scorer-->>Engine: RiskAssessment (Level, Score, Rationale)
    Engine-->>UI: AnalysisResult
    UI->>Evd: recordEvidence(message, caseId)
    Evd->>DB: saveEvidence() & saveEmailMessage()
    DB-->>UI: Stored & Audited
    UI-->>Analyst: Displays Risk Badge, Explainable Score & Evidence
```

---

## 3. Explainable Risk Scoring Engine

### Scoring Philosophy:
Traditional anti-spam filters often suffer from **correlated score inflation** (e.g., an email mentioning an "urgent deadline" multiple times gets heavily penalized in duplicate). MailShield employs **Category Ceiling Caps** to avoid multi-counting while guaranteeing that any confirmed critical threat (such as a disguised executable payload or bare IP phishing lure) immediately elevates the baseline verdict.

### Category Ceiling Caps:
| Detection Category | Base Rule Points | Max Category Contribution | Rational & Mitigation |
|---|---|---|---|
| `SUSPICIOUS_ATTACHMENT` | 35 - 50 | **50 pts** | High lethal potential (executables, double extensions) |
| `SUSPICIOUS_URL` | 20 - 35 | **45 pts** | Deceptive anchor text mismatch, IP hosts, homoglyphs |
| `THREAT_INTELLIGENCE` | 20 - 40 | **45 pts** | Flagged reputation matches from verified feeds |
| `SPOOFING_IMPERSONATION`| 20 - 35 | **40 pts** | Display-name executive spoofing, embedded emails |
| `AUTHENTICATION_FAILURE`| 15 - 30 | **35 pts** | Parsed SPF fail, DKIM fail, DMARC alignment fail |
| `SOCIAL_ENGINEERING` | 15 - 25 | **30 pts** | Urgency, account suspension threats, wire transfers |
| `HEADER_ANOMALY` | 5 - 20 | **25 pts** | From vs Reply-To domain divergence, Return-Path |
| `CONTENT_HEURISTIC` | 5 - 15 | **20 pts** | Formatting and minor stylistic anomalies |

### Risk Level Thresholds:
- **0 - 24 / 100:** `LOW RISK` (Benign email, passed standard checks)
- **25 - 54 / 100:** `MEDIUM RISK` (Anomalies observed; exercise caution)
- **55 - 79 / 100:** `HIGH RISK` (Strong threat indicators present; secondary channel verification required)
- **80 - 100 / 100:** `CRITICAL THREAT` (Confirmed malicious payload, severe spoofing, or deceptive phishing lure)
- `INSUFFICIENT_DATA`: Missing headers and body (cannot reach a valid verdict)

