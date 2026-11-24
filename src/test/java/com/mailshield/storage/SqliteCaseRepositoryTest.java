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

        List<EvidenceRecord> emailEvidence = repository.findEvidenceByEmailId("EVD-01");
        assertThat(emailEvidence).isEmpty(); // Not yet associated with an emailId
    }

    @Test
    @DisplayName("Should persist full email content and metadata for deep SOC inspection")
    void testFullEmailContentPersistenceAndRetrieval() {
        EmailMessage fullMsg = EmailMessage.builder()
                .id("msg-full-01")
                .providerMessageId("prov-full-01")
                .providerSource(ProviderType.GMAIL)
                .fromAddress("ciso@enterprise.com")
                .fromDisplayName("Chief Information Security Officer")
                .from("Chief Information Security Officer <ciso@enterprise.com>")
                .replyTo("attacker@spoofed.com")
                .returnPath("ciso@enterprise.com")
                .subject("URGENT: Executive Wire Transfer Authorization")
                .bodyText("Please authorize the $78,500 wire immediately.\nConfidential under NDA.")
                .bodyHtml("<html><body><p>Please authorize the <strong>$78,500</strong> wire immediately.</p></body></html>")
                .headers(List.of(
                        new EmailHeader("From", "Chief Information Security Officer <ciso@enterprise.com>"),
                        new EmailHeader("Reply-To", "attacker@spoofed.com"),
                        new EmailHeader("X-Mailer", "Outlook 2026")
                ))
                .attachments(List.of(
                        new EmailAttachmentMetadata("Invoice_Wire.pdf.exe", "application/x-msdownload", 45000, "abc123hash", true, "Double Extension")
                ))
                .extractedUrls(List.of(
                        new ExtractedUrl("http://198.51.100.55/login", "http://198.51.100.55/login", "198.51.100.55", "/login", "http", "portal.company.com", false, true, false, false, false, true, List.of("Direct IP", "Anchor Mismatch"))
                ))
                .authResult(new AuthenticationResult(
                        AuthenticationResult.AuthStatus.FAIL, "sender@evil.com",
                        AuthenticationResult.AuthStatus.FAIL, "evil.com",
                        AuthenticationResult.AuthStatus.FAIL, "reject", "raw-auth-header", true
                ))
                .rawSha256("d41d8cd98f00b204e9800998ecf8427e")
                .build();

        repository.saveEmailMessage(fullMsg);

        Optional<EmailMessage> retrieved = repository.findEmailMessageById("msg-full-01");
        assertThat(retrieved).isPresent();
        EmailMessage m = retrieved.get();
        assertThat(m.getBodyText()).contains("wire immediately");
        assertThat(m.getBodyHtml()).contains("<strong>$78,500</strong>");
        assertThat(m.getHeaders()).hasSize(3);
        assertThat(m.getAttachments()).hasSize(1);
        assertThat(m.getAttachments().get(0).getFilename()).isEqualTo("Invoice_Wire.pdf.exe");
        assertThat(m.getExtractedUrls()).hasSize(1);
        assertThat(m.getExtractedUrls().get(0).isMismatchWithAnchor()).isTrue();
        assertThat(m.getAuthResult().getSpfStatus()).isEqualTo(AuthenticationResult.AuthStatus.FAIL);
    }
}

