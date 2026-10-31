package com.mailshield.storage;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.mailshield.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.lang.reflect.Type;
import java.sql.*;
import java.time.Instant;
import java.util.*;

/**
 * Robust embedded SQLite repository for forensic evidence, cases, email records, and checkpoints.
 * Employs parameterized queries to eliminate SQL injection vulnerabilities.
 */
public class SqliteCaseRepository implements CaseRepository {

    private static final Logger log = LoggerFactory.getLogger(SqliteCaseRepository.class);
    private final String dbUrl;
    private final Gson gson = new Gson();

    public SqliteCaseRepository(String dbFilePath) {
        File dbFile = new File(dbFilePath);
        File parent = dbFile.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
        this.dbUrl = "jdbc:sqlite:" + dbFilePath;
        initializeSchema();
    }

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection(dbUrl);
    }

    private void initializeSchema() {
        String[] ddlStatements = {
            "CREATE TABLE IF NOT EXISTS emails (" +
                "id TEXT PRIMARY KEY, " +
                "provider_id TEXT UNIQUE, " +
                "provider_source TEXT, " +
                "from_addr TEXT, " +
                "from_display_name TEXT, " +
                "reply_to TEXT, " +
                "return_path TEXT, " +
                "subject TEXT, " +
                "sent_date TEXT, " +
                "body_preview TEXT, " +
                "raw_sha256 TEXT, " +
                "ingested_at TEXT" +
            ");",

            "CREATE TABLE IF NOT EXISTS analyses (" +
                "analysis_id TEXT PRIMARY KEY, " +
                "email_id TEXT UNIQUE, " +
                "risk_level TEXT, " +
                "score INTEGER, " +
                "confidence REAL, " +
                "rationale TEXT, " +
                "rule_version TEXT, " +
                "analyzed_at TEXT, " +
                "findings_json TEXT, " +
                "intel_json TEXT, " +
                "FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE" +
            ");",

            "CREATE TABLE IF NOT EXISTS cases (" +
                "case_id TEXT PRIMARY KEY, " +
                "title TEXT, " +
                "status TEXT, " +
                "priority TEXT, " +
                "created_at TEXT, " +
                "updated_at TEXT, " +
                "analyst_notes TEXT, " +
                "assigned_analyst TEXT, " +
                "tags TEXT" +
            ");",

            "CREATE TABLE IF NOT EXISTS case_associations (" +
                "case_id TEXT, " +
                "email_id TEXT, " +
                "PRIMARY KEY (case_id, email_id), " +
                "FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE, " +
                "FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE" +
            ");",

            "CREATE TABLE IF NOT EXISTS evidence_records (" +
                "evidence_id TEXT PRIMARY KEY, " +
                "case_id TEXT, " +
                "email_id TEXT, " +
                "raw_sha256 TEXT, " +
                "normalized_sha256 TEXT, " +
                "hash_algorithm TEXT, " +
                "recorded_at TEXT, " +
                "evidence_type TEXT, " +
                "source_description TEXT, " +
                "original_byte_size INTEGER, " +
                "integrity_notes TEXT" +
            ");",

            "CREATE TABLE IF NOT EXISTS monitoring_checkpoints (" +
                "provider_key TEXT PRIMARY KEY, " +
                "last_checkpoint TEXT, " +
                "updated_at TEXT" +
            ");",

            "CREATE INDEX IF NOT EXISTS idx_emails_provider_id ON emails(provider_id);",
            "CREATE INDEX IF NOT EXISTS idx_analyses_risk_level ON analyses(risk_level);",
            "CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);"
        };

        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            for (String sql : ddlStatements) {
                stmt.execute(sql);
            }
            log.info("SQLite database schema initialized successfully at {}", dbUrl);
        } catch (SQLException e) {
            log.error("Fatal error creating SQLite schema: {}", e.getMessage(), e);
            throw new RuntimeException("Database initialization failed", e);
        }
    }

    @Override
    public void saveEmailMessage(EmailMessage message) {
        String sql = "INSERT OR REPLACE INTO emails (id, provider_id, provider_source, from_addr, " +
                "from_display_name, reply_to, return_path, subject, sent_date, body_preview, raw_sha256, ingested_at) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, message.getId());
            ps.setString(2, message.getProviderMessageId());
            ps.setString(3, message.getProviderSource().name());
            ps.setString(4, message.getFromAddress());
            ps.setString(5, message.getFromDisplayName());
            ps.setString(6, message.getReplyTo());
            ps.setString(7, message.getReturnPath());
            ps.setString(8, message.getSubject());
            ps.setString(9, message.getDate().toString());
            // Truncate preview to prevent storing unnecessary body text
            String preview = message.getBodyText();
            if (preview.length() > 500) preview = preview.substring(0, 500) + "...";
            ps.setString(10, preview);
            ps.setString(11, message.getRawSha256());
            ps.setString(12, message.getIngestedAt().toString());
            ps.executeUpdate();
        } catch (SQLException e) {
            log.error("Failed to save email message: {}", e.getMessage(), e);
        }
    }

    @Override
    public Optional<EmailMessage> findEmailMessageById(String id) {
        String sql = "SELECT * FROM emails WHERE id = ?";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapResultSetToEmail(rs));
                }
            }
        } catch (SQLException e) {
            log.error("Error finding email by ID {}: {}", id, e.getMessage(), e);
        }
        return Optional.empty();
    }

    @Override
    public Optional<EmailMessage> findEmailMessageByProviderId(String providerMessageId) {
        String sql = "SELECT * FROM emails WHERE provider_id = ?";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, providerMessageId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapResultSetToEmail(rs));
                }
            }
        } catch (SQLException e) {
            log.error("Error finding email by provider ID: {}", e.getMessage(), e);
        }
        return Optional.empty();
    }

    @Override
    public boolean hasEmailBeenProcessed(String providerMessageId) {
        String sql = "SELECT 1 FROM emails WHERE provider_id = ? LIMIT 1";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, providerMessageId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            log.error("Error checking processed status: {}", e.getMessage(), e);
            return false;
        }
    }

    @Override
    public List<EmailMessage> findAllEmails(int limit, int offset) {
        String sql = "SELECT * FROM emails ORDER BY datetime(ingested_at) DESC LIMIT ? OFFSET ?";
        List<EmailMessage> list = new ArrayList<>();
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, limit);
            ps.setInt(2, offset);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(mapResultSetToEmail(rs));
                }
            }
        } catch (SQLException e) {
            log.error("Error fetching email list: {}", e.getMessage(), e);
        }
        return list;
    }

    @Override
    public int getTotalEmailCount() {
        String sql = "SELECT COUNT(*) FROM emails";
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) return rs.getInt(1);
        } catch (SQLException e) {
            log.error("Error counting emails: {}", e.getMessage(), e);
        }
        return 0;
    }

    @Override
    public void saveAnalysisResult(AnalysisResult result) {
        String sql = "INSERT OR REPLACE INTO analyses (analysis_id, email_id, risk_level, score, " +
                "confidence, rationale, rule_version, analyzed_at, findings_json, intel_json) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, result.getAnalysisId());
            ps.setString(2, result.getEmailMessageId());
            ps.setString(3, result.getRiskAssessment().getRiskLevel().name());
            ps.setInt(4, result.getRiskAssessment().getScore());
            ps.setDouble(5, result.getRiskAssessment().getAggregateConfidence());
            ps.setString(6, result.getRiskAssessment().getExplanation());
            ps.setString(7, result.getRuleEngineVersion());
            ps.setString(8, result.getAnalyzedAt().toString());
            ps.setString(9, gson.toJson(result.getFindings()));
            ps.setString(10, gson.toJson(result.getIntelligenceReports()));
            ps.executeUpdate();
        } catch (SQLException e) {
            log.error("Error saving analysis result: {}", e.getMessage(), e);
        }
    }

    @Override
    public Optional<AnalysisResult> findAnalysisResultByEmailId(String emailId) {
        String sql = "SELECT * FROM analyses WHERE email_id = ?";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, emailId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapResultSetToAnalysis(rs));
                }
            }
        } catch (SQLException e) {
            log.error("Error finding analysis by email ID: {}", e.getMessage(), e);
        }
        return Optional.empty();
    }

    @Override
    public List<AnalysisResult> findRecentAnalyses(int limit) {
        String sql = "SELECT * FROM analyses ORDER BY datetime(analyzed_at) DESC LIMIT ?";
        List<AnalysisResult> list = new ArrayList<>();
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(mapResultSetToAnalysis(rs));
                }
            }
        } catch (SQLException e) {
            log.error("Error fetching recent analyses: {}", e.getMessage(), e);
        }
        return list;
    }

    @Override
    public void saveCase(InvestigationCase c) {
        String sql = "INSERT OR REPLACE INTO cases (case_id, title, status, priority, created_at, " +
                "updated_at, analyst_notes, assigned_analyst, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, c.getCaseId());
            ps.setString(2, c.getTitle());
            ps.setString(3, c.getStatus().name());
            ps.setString(4, c.getPriority().name());
            ps.setString(5, c.getCreatedAt().toString());
            ps.setString(6, c.getUpdatedAt().toString());
            ps.setString(7, c.getAnalystNotes());
            ps.setString(8, c.getAssignedAnalyst());
            ps.setString(9, String.join(",", c.getTags()));
            ps.executeUpdate();

            // Associations
            for (String emailId : c.getAssociatedMessageIds()) {
                String assocSql = "INSERT OR IGNORE INTO case_associations (case_id, email_id) VALUES (?, ?)";
                try (PreparedStatement aps = conn.prepareStatement(assocSql)) {
                    aps.setString(1, c.getCaseId());
                    aps.setString(2, emailId);
                    aps.executeUpdate();
                }
            }
        } catch (SQLException e) {
            log.error("Error saving case: {}", e.getMessage(), e);
        }
    }

    @Override
    public Optional<InvestigationCase> findCaseById(String caseId) {
        String sql = "SELECT * FROM cases WHERE case_id = ?";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, caseId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapResultSetToCase(conn, rs));
                }
            }
        } catch (SQLException e) {
            log.error("Error finding case by ID: {}", e.getMessage(), e);
        }
        return Optional.empty();
    }

    @Override
    public List<InvestigationCase> findAllCases(int limit, int offset) {
        String sql = "SELECT * FROM cases ORDER BY datetime(created_at) DESC LIMIT ? OFFSET ?";
        List<InvestigationCase> list = new ArrayList<>();
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, limit);
            ps.setInt(2, offset);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(mapResultSetToCase(conn, rs));
                }
            }
        } catch (SQLException e) {
            log.error("Error fetching cases: {}", e.getMessage(), e);
        }
        return list;
    }

    @Override
    public int getTotalCaseCount() {
        String sql = "SELECT COUNT(*) FROM cases";
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) return rs.getInt(1);
        } catch (SQLException e) {
            log.error("Error counting cases: {}", e.getMessage(), e);
        }
        return 0;
    }

    @Override
    public void updateCaseNotes(String caseId, String notes, String status) {
        String sql = "UPDATE cases SET analyst_notes = ?, status = ?, updated_at = ? WHERE case_id = ?";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, notes);
            ps.setString(2, status);
            ps.setString(3, Instant.now().toString());
            ps.setString(4, caseId);
            ps.executeUpdate();
        } catch (SQLException e) {
            log.error("Error updating case notes: {}", e.getMessage(), e);
        }
    }

    @Override
    public void saveEvidence(EvidenceRecord record) {
        String sql = "INSERT OR REPLACE INTO evidence_records (evidence_id, case_id, email_id, " +
                "raw_sha256, normalized_sha256, hash_algorithm, recorded_at, evidence_type, " +
                "source_description, original_byte_size, integrity_notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, record.getEvidenceId());
            ps.setString(2, record.getCaseId());
            ps.setString(3, "");
            ps.setString(4, record.getRawMessageSha256());
            ps.setString(5, record.getNormalizedContentSha256());
            ps.setString(6, record.getHashAlgorithm());
            ps.setString(7, record.getRecordedAt().toString());
            ps.setString(8, record.getEvidenceType());
            ps.setString(9, record.getSourceDescription());
            ps.setLong(10, record.getOriginalByteSize());
            ps.setString(11, record.getIntegrityNotes());
            ps.executeUpdate();
        } catch (SQLException e) {
            log.error("Error saving evidence record: {}", e.getMessage(), e);
        }
    }

    @Override
    public List<EvidenceRecord> findEvidenceByCaseId(String caseId) {
        String sql = "SELECT * FROM evidence_records WHERE case_id = ? ORDER BY datetime(recorded_at) ASC";
        List<EvidenceRecord> list = new ArrayList<>();
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, caseId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(new EvidenceRecord(
                            rs.getString("evidence_id"),
                            rs.getString("case_id"),
                            rs.getString("raw_sha256"),
                            rs.getString("normalized_sha256"),
                            rs.getString("hash_algorithm"),
                            Instant.parse(rs.getString("recorded_at")),
                            rs.getString("evidence_type"),
                            rs.getString("source_description"),
                            rs.getLong("original_byte_size"),
                            rs.getString("integrity_notes")
                    ));
                }
            }
        } catch (SQLException e) {
            log.error("Error fetching evidence for case: {}", e.getMessage(), e);
        }
        return list;
    }

    @Override
    public void saveCheckpoint(String providerKey, String lastCheckpoint) {
        String sql = "INSERT OR REPLACE INTO monitoring_checkpoints (provider_key, last_checkpoint, updated_at) VALUES (?, ?, ?)";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, providerKey);
            ps.setString(2, lastCheckpoint);
            ps.setString(3, Instant.now().toString());
            ps.executeUpdate();
        } catch (SQLException e) {
            log.error("Error saving checkpoint: {}", e.getMessage(), e);
        }
    }

    @Override
    public Optional<String> getCheckpoint(String providerKey) {
        String sql = "SELECT last_checkpoint FROM monitoring_checkpoints WHERE provider_key = ?";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, providerKey);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return Optional.ofNullable(rs.getString(1));
            }
        } catch (SQLException e) {
            log.error("Error retrieving checkpoint: {}", e.getMessage(), e);
        }
        return Optional.empty();
    }

    @Override
    public int getHighRiskEmailCount() {
        String sql = "SELECT COUNT(*) FROM analyses WHERE risk_level = 'HIGH'";
        try (Connection conn = getConnection(); Statement s = conn.createStatement(); ResultSet rs = s.executeQuery(sql)) {
            if (rs.next()) return rs.getInt(1);
        } catch (SQLException ignored) {}
        return 0;
    }

    @Override
    public int getCriticalEmailCount() {
        String sql = "SELECT COUNT(*) FROM analyses WHERE risk_level = 'CRITICAL'";
        try (Connection conn = getConnection(); Statement s = conn.createStatement(); ResultSet rs = s.executeQuery(sql)) {
            if (rs.next()) return rs.getInt(1);
        } catch (SQLException ignored) {}
        return 0;
    }

    @Override
    public int getOpenCaseCount() {
        String sql = "SELECT COUNT(*) FROM cases WHERE status IN ('OPEN', 'UNDER_INVESTIGATION', 'ESCALATED')";
        try (Connection conn = getConnection(); Statement s = conn.createStatement(); ResultSet rs = s.executeQuery(sql)) {
            if (rs.next()) return rs.getInt(1);
        } catch (SQLException ignored) {}
        return 0;
    }

    @Override
    public void close() {
        // SQLite in JDBC automatically releases file handles when statements/connections are closed
    }

    private EmailMessage mapResultSetToEmail(ResultSet rs) throws SQLException {
        ProviderType pType = ProviderType.MANUAL_PASTE;
        try {
            pType = ProviderType.valueOf(rs.getString("provider_source"));
        } catch (Exception ignored) {}

        return EmailMessage.builder()
                .id(rs.getString("id"))
                .providerMessageId(rs.getString("provider_id"))
                .providerSource(pType)
                .fromAddress(rs.getString("from_addr"))
                .fromDisplayName(rs.getString("from_display_name"))
                .from(rs.getString("from_display_name") + " <" + rs.getString("from_addr") + ">")
                .replyTo(rs.getString("reply_to"))
                .returnPath(rs.getString("return_path"))
                .subject(rs.getString("subject"))
                .date(Instant.parse(rs.getString("sent_date")))
                .bodyText(rs.getString("body_preview"))
                .rawSha256(rs.getString("raw_sha256"))
                .ingestedAt(Instant.parse(rs.getString("ingested_at")))
                .build();
    }

    private AnalysisResult mapResultSetToAnalysis(ResultSet rs) throws SQLException {
        RiskLevel rLevel = RiskLevel.INSUFFICIENT_DATA;
        try {
            rLevel = RiskLevel.valueOf(rs.getString("risk_level"));
        } catch (Exception ignored) {}

        Type findingListType = new TypeToken<ArrayList<Finding>>(){}.getType();
        Type stringListType = new TypeToken<ArrayList<String>>(){}.getType();

        List<Finding> findings = gson.fromJson(rs.getString("findings_json"), findingListType);
        List<String> intel = gson.fromJson(rs.getString("intel_json"), stringListType);

        RiskAssessment assessment = new RiskAssessment(
                rLevel,
                rs.getInt("score"),
                rs.getDouble("confidence"),
                rs.getString("rationale"),
                Collections.emptyMap(),
                rs.getString("rule_version"),
                false
        );

        return new AnalysisResult(
                rs.getString("analysis_id"),
                rs.getString("email_id"),
                assessment,
                findings != null ? findings : Collections.emptyList(),
                intel != null ? intel : Collections.emptyList(),
                Instant.parse(rs.getString("analyzed_at")),
                rs.getString("rule_version")
        );
    }

    private InvestigationCase mapResultSetToCase(Connection conn, ResultSet rs) throws SQLException {
        String caseId = rs.getString("case_id");
        List<String> associatedEmails = new ArrayList<>();
        String assocSql = "SELECT email_id FROM case_associations WHERE case_id = ?";
        try (PreparedStatement ps = conn.prepareStatement(assocSql)) {
            ps.setString(1, caseId);
            try (ResultSet ars = ps.executeQuery()) {
                while (ars.next()) {
                    associatedEmails.add(ars.getString("email_id"));
                }
            }
        }

        String tagsStr = rs.getString("tags");
        List<String> tags = tagsStr != null && !tagsStr.isBlank() ? Arrays.asList(tagsStr.split(",")) : Collections.emptyList();

        CaseStatus st = CaseStatus.OPEN;
        try { st = CaseStatus.valueOf(rs.getString("status")); } catch (Exception ignored) {}

        CasePriority pr = CasePriority.MEDIUM;
        try { pr = CasePriority.valueOf(rs.getString("priority")); } catch (Exception ignored) {}

        return InvestigationCase.builder()
                .caseId(caseId)
                .title(rs.getString("title"))
                .status(st)
                .priority(pr)
                .createdAt(Instant.parse(rs.getString("created_at")))
                .updatedAt(Instant.parse(rs.getString("updated_at")))
                .analystNotes(rs.getString("analyst_notes"))
                .assignedAnalyst(rs.getString("assigned_analyst"))
                .associatedMessageIds(associatedEmails)
                .tags(tags)
                .build();
    }
}

