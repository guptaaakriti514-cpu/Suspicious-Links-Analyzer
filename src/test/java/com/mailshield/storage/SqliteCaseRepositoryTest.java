package com.mailshield.storage;

import com.mailshield.model.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

public class SqliteCaseRepositoryTest {

    @TempDir
    Path tempDir;

    private SqliteCaseRepository repository;
    private File dbFile;

    @BeforeEach
    void setUp() {
        dbFile = tempDir.resolve("test_mailshield.db").toFile();
        repository = new SqliteCaseRepository(dbFile.getAbsolutePath());
    }

    @AfterEach
    void tearDown() {
        if (repository != null) {
            repository.close();
        }
    }

    @Test
    @DisplayName("Should persist and retrieve email message and prevent duplicate processing")
    void testEmailPersistenceAndDeduplication() {
        EmailMessage msg = EmailMessage.builder()
                .id("msg-001")
                .providerMessageId("prov-msg-999")
                .providerSource(ProviderType.GMAIL)
                .fromAddress("sender@domain.com")
                .fromDisplayName("Sender Name")
                .subject("Test Invoice")
                .bodyText("Payment invoice body.")
                .rawSha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .build();

        assertThat(repository.hasEmailBeenProcessed("prov-msg-999")).isFalse();
        repository.saveEmailMessage(msg);

        assertThat(repository.hasEmailBeenProcessed("prov-msg-999")).isTrue();
        Optional<EmailMessage> retrieved = repository.findEmailMessageById("msg-001");
        assertThat(retrieved).isPresent();
        assertThat(retrieved.get().getSubject()).isEqualTo("Test Invoice");
        assertThat(retrieved.get().getFromAddress()).isEqualTo("sender@domain.com");
    }

    @Test
    @DisplayName("Should persist and retrieve analysis result and risk assessment")
    void testAnalysisResultPersistence() {
        RiskAssessment assessment = new RiskAssessment(
                RiskLevel.CRITICAL, 95, 0.94,
                "Critical phishing indicator detected.",
                java.util.Collections.emptyMap(), "2.1.0", false
        );

        AnalysisResult result = new AnalysisResult(
                "an-001", "msg-001", assessment,
                List.of(Finding.builder().ruleId("SOC-001").severity(Severity.CRITICAL).build()),
                List.of("Intel Report"),
                Instant.now(), "2.1.0"
        );

        repository.saveAnalysisResult(result);
        Optional<AnalysisResult> retrieved = repository.findAnalysisResultByEmailId("msg-001");
        assertThat(retrieved).isPresent();
        assertThat(retrieved.get().getRiskAssessment().getRiskLevel()).isEqualTo(RiskLevel.CRITICAL);
        assertThat(retrieved.get().getRiskAssessment().getScore()).isEqualTo(95);
        assertThat(retrieved.get().getFindings()).hasSize(1);
    }

    @Test
    @DisplayName("Should persist, query, and update investigation cases and evidence")
    void testCaseAndEvidenceLifecycle() {
        InvestigationCase c = InvestigationCase.builder()
                .caseId("CASE-TEST-100")
                .title("Suspicious Executive Impersonation")
                .status(CaseStatus.OPEN)
                .priority(CasePriority.HIGH)
                .analystNotes("Initial triage underway.")
                .associatedMessageIds(List.of("msg-001"))
                .build();

        repository.saveCase(c);
        assertThat(repository.getTotalCaseCount()).isEqualTo(1);

        repository.updateCaseNotes("CASE-TEST-100", "Updated: Attacker IP quarantined.", CaseStatus.UNDER_INVESTIGATION.name());
        Optional<InvestigationCase> updated = repository.findCaseById("CASE-TEST-100");
        assertThat(updated).isPresent();
        assertThat(updated.get().getStatus()).isEqualTo(CaseStatus.UNDER_INVESTIGATION);
        assertThat(updated.get().getAnalystNotes()).contains("Attacker IP quarantined");

        // Evidence
        EvidenceRecord ev = new EvidenceRecord(
                "EVD-01", "CASE-TEST-100", "rawhash123", "normhash456", "SHA-256",
                Instant.now(), "RFC 5322", "Manual Ingest", 1024, "Integrity verified"
        );
        repository.saveEvidence(ev);

        List<EvidenceRecord> evidenceList = repository.findEvidenceByCaseId("CASE-TEST-100");
        assertThat(evidenceList).hasSize(1);
        assertThat(evidenceList.get(0).getRawMessageSha256()).isEqualTo("rawhash123");
    }
}

