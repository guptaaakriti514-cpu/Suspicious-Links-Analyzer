package com.mailshield.services;

import com.mailshield.detection.*;
import com.mailshield.forensics.DefaultEvidenceManager;
import com.mailshield.forensics.EvidenceManager;
import com.mailshield.model.*;
import com.mailshield.scoring.DefaultRiskScoringEngine;
import com.mailshield.storage.CaseRepository;
import com.mailshield.storage.SqliteCaseRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

class EmailAnalysisServiceTest {

    @TempDir
    File tempDir;

    private CaseRepository repository;
    private EmailAnalysisService analysisService;
    private NotificationService notificationService;

    @BeforeEach
    void setUp() {
        File dbFile = new File(tempDir, "test_analysis.db");
        repository = new SqliteCaseRepository(dbFile.getAbsolutePath());
        EvidenceManager evidenceManager = new DefaultEvidenceManager(repository);
        notificationService = new NotificationService();

        DetectionEngine detectionEngine = new DetectionEngine(
                new SafeHeaderAnalyzer(),
                new SafeContentAnalyzer(),
                new SafeUrlAnalyzer(),
                new SafeAttachmentAnalyzer(),
                null,
                new DefaultRiskScoringEngine()
        );
        ThreatDetectionService threatService = new ThreatDetectionService(detectionEngine, null);
        analysisService = new EmailAnalysisService(threatService, repository, evidenceManager, notificationService);
    }

    @Test
    void shouldProcessAndPersistCleanEmail() {
        EmailMessage cleanMsg = EmailMessage.builder()
                .id("clean-msg-01")
                .providerMessageId("prov-clean-01")
                .providerSource(ProviderType.GMAIL)
                .from("support@legit-service.com")
                .fromAddress("support@legit-service.com")
                .to(List.of("user@mailshield.io"))
                .subject("Quarterly Account Security Summary")
                .date(Instant.now())
                .bodyText("Hello, please find your quarterly account summary attached. Regards.")
                .rawBytes("Clean message raw payload".getBytes())
                .ingestedAt(Instant.now())
                .build();

        AnalysisResult result = analysisService.processAndPersist(cleanMsg);

        assertThat(result).isNotNull();
        assertThat(result.getEmailMessageId()).isEqualTo("clean-msg-01");
        assertThat(result.getRiskAssessment().getRiskLevel()).isEqualTo(RiskLevel.LOW);

        Optional<EmailMessage> retrieved = analysisService.getEmail("clean-msg-01");
        assertThat(retrieved).isPresent();
        assertThat(retrieved.get().getSubject()).isEqualTo("Quarterly Account Security Summary");

        Optional<AnalysisResult> storedAnalysis = analysisService.getAnalysis("clean-msg-01");
        assertThat(storedAnalysis).isPresent();
        assertThat(analysisService.getTotalEmailsAnalyzed()).isEqualTo(1);
    }

    @Test
    void shouldPublishAlertWhenHighRiskThreatDetected() {
        AtomicBoolean alertFired = new AtomicBoolean(false);
        notificationService.addListener(new NotificationService.NotificationListener() {
            @Override
            public void onSecurityAlert(NotificationService.SecurityAlert alert) {
                if (alert.severity().equals("CRITICAL") || alert.severity().equals("HIGH")) {
                    alertFired.set(true);
                }
            }

            @Override
            public void onProviderStatusChanged(ProviderType providerType, boolean connected, String accountEmail) {}

            @Override
            public void onSyncProgress(ProviderType providerType, String message, int newEmailsCount) {}
        });

        // Email with suspicious executable attachment
        EmailMessage maliciousMsg = EmailMessage.builder()
                .id("threat-msg-02")
                .providerMessageId("prov-threat-02")
                .providerSource(ProviderType.OUTLOOK)
                .from("invoice@urgent-billing-dept.com")
                .fromAddress("invoice@urgent-billing-dept.com")
                .to(List.of("victim@workplace.com"))
                .subject("URGENT: Outstanding Payment Notice Action Required Immediately")
                .date(Instant.now())
                .bodyText("Immediate wire payment required or account suspended. Open attachment.")
                .attachments(List.of(
                        new EmailAttachmentMetadata("invoice_overdue.vbs", "application/octet-stream", 45000,
                                "sha256-payload", true, "executable_script")
                ))
                .rawBytes("Threat message bytes".getBytes())
                .ingestedAt(Instant.now())
                .build();

        AnalysisResult result = analysisService.processAndPersist(maliciousMsg);

        assertThat(result.getRiskAssessment().getScore()).isGreaterThanOrEqualTo(50);
        assertThat(alertFired.get()).isTrue();
    }
}
