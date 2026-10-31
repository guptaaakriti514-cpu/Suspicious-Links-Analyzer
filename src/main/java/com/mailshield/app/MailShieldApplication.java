package com.mailshield.app;

import com.mailshield.config.AppConfig;
import com.mailshield.detection.*;
import com.mailshield.forensics.DefaultEvidenceManager;
import com.mailshield.forensics.EvidenceManager;
import com.mailshield.ingestion.EmailParser;
import com.mailshield.ingestion.SafeEmailParser;
import com.mailshield.intelligence.LocalThreatIntelligenceService;
import com.mailshield.intelligence.ThreatIntelligenceService;
import com.mailshield.model.*;
import com.mailshield.monitoring.DefaultMonitoringService;
import com.mailshield.monitoring.MonitoringService;
import com.mailshield.providers.EmailProvider;
import com.mailshield.providers.GoogleGmailProvider;
import com.mailshield.providers.MicrosoftOutlookProvider;
import com.mailshield.reporting.HtmlReportGenerator;
import com.mailshield.reporting.ReportGenerator;
import com.mailshield.scoring.DefaultRiskScoringEngine;
import com.mailshield.scoring.RiskScoringEngine;
import com.mailshield.security.CredentialStore;
import com.mailshield.security.DefaultCredentialStore;
import com.mailshield.storage.CaseRepository;
import com.mailshield.storage.SqliteCaseRepository;
import com.mailshield.ui.MailShieldMainWindow;
import com.mailshield.ui.UiTheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.awt.GraphicsEnvironment;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * MailShield Platform Application Bootstrap & Entry Point.
 * Assembles services, initializes local SQLite repositories, seeds initial demo fixtures if empty,
 * and launches the Dark SOC Desktop UI.
 */
public class MailShieldApplication {

    private static final Logger log = LoggerFactory.getLogger(MailShieldApplication.class);

    public static void main(String[] args) {
        log.info("Starting MailShield Threat Detection Platform on Java {}", System.getProperty("java.version"));

        // Setup Modern FlatLaf SOC Dark Look & Feel
        UiTheme.setupFlatLaf();

        try {
            // 1. Config & Core Services
            AppConfig appConfig = AppConfig.getInstance();
            CredentialStore credentialStore = new DefaultCredentialStore(appConfig.getDataDir());
            CaseRepository caseRepository = new SqliteCaseRepository(appConfig.getDbPath());
            EvidenceManager evidenceManager = new DefaultEvidenceManager(caseRepository);
            ReportGenerator reportGenerator = new HtmlReportGenerator();

            // 2. Detection Analyzers & Scoring Engine
            HeaderAnalyzer headerAnalyzer = new SafeHeaderAnalyzer();
            ContentAnalyzer contentAnalyzer = new SafeContentAnalyzer();
            SafeUrlAnalyzer urlAnalyzer = new SafeUrlAnalyzer();
            AttachmentMetadataAnalyzer attachmentAnalyzer = new SafeAttachmentAnalyzer();
            ThreatIntelligenceService threatIntel = new LocalThreatIntelligenceService(appConfig.getVirusTotalApiKey());
            RiskScoringEngine scoringEngine = new DefaultRiskScoringEngine();

            EmailParser emailParser = new SafeEmailParser(urlAnalyzer);
            DetectionEngine detectionEngine = new DetectionEngine(
                    headerAnalyzer, contentAnalyzer, urlAnalyzer, attachmentAnalyzer, threatIntel, scoringEngine
            );

            // 3. Email Ingestion Providers
            Map<ProviderType, EmailProvider> providers = new EnumMap<>(ProviderType.class);
            EmailProvider gmailProvider = new GoogleGmailProvider(emailParser, caseRepository, appConfig);
            EmailProvider outlookProvider = new MicrosoftOutlookProvider(emailParser, caseRepository, appConfig);
            providers.put(ProviderType.GMAIL, gmailProvider);
            providers.put(ProviderType.OUTLOOK, outlookProvider);

            // 4. Monitoring Service
            MonitoringService monitoringService = new DefaultMonitoringService(
                    providers, detectionEngine, caseRepository, evidenceManager
            );
            monitoringService.setPollIntervalSeconds(appConfig.getPollIntervalSeconds());

            // 5. Seed initial demo scenarios into database if empty for immediate demonstration
            seedDemoDataIfEmpty(emailParser, detectionEngine, caseRepository, evidenceManager);

            // 6. Launch Desktop UI on Swing Event Dispatch Thread (if not headless)
            if (!GraphicsEnvironment.isHeadless()) {
                SwingUtilities.invokeLater(() -> {
                    MailShieldMainWindow window = new MailShieldMainWindow(
                            appConfig,
                            emailParser,
                            detectionEngine,
                            caseRepository,
                            evidenceManager,
                            reportGenerator,
                            monitoringService,
                            credentialStore,
                            providers
                    );
                    window.setVisible(true);
                    log.info("MailShield SOC Desktop GUI is active.");
                });
            } else {
                log.info("Running in headless terminal mode. Core detection engine and repositories initialized successfully.");
            }

            // Register Graceful Shutdown Hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                log.info("Shutting down MailShield services...");
                monitoringService.stopMonitoring();
                caseRepository.close();
            }));

        } catch (Exception e) {
            log.error("Fatal exception during application startup: {}", e.getMessage(), e);
            System.err.println("Fatal startup error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Seeds initial synthetic demo emails and incident cases into SQLite on first run
     * so examiners and users immediately experience a populated, realistic SOC operations center.
     */
    public static void seedDemoDataIfEmpty(EmailParser emailParser,
                                          DetectionEngine detectionEngine,
                                          CaseRepository caseRepository,
                                          EvidenceManager evidenceManager) {
        if (caseRepository.getTotalEmailCount() > 0) {
            return; // Already populated
        }

        log.info("Empty database detected. Seeding initial synthetic demo fixtures for viva demonstration...");

        var fixtures = DemoDataFixtures.getAvailableFixtures();
        for (int i = 0; i < fixtures.size(); i++) {
            var item = fixtures.get(i);
            try {
                EmailMessage message = emailParser.parseRawText(item.getRawContent());
                AnalysisResult result = detectionEngine.analyzeEmail(message);

                caseRepository.saveEmailMessage(message);
                caseRepository.saveAnalysisResult(result);
                evidenceManager.recordEvidence(message, null, "Synthetic Demo Seed: " + item.getTitle());

                // If high or critical, create an initial incident case
                if (result.getRiskAssessment().getRiskLevel() == RiskLevel.CRITICAL ||
                    result.getRiskAssessment().getRiskLevel() == RiskLevel.HIGH) {

                    InvestigationCase c = InvestigationCase.builder()
                            .caseId("CASE-2026-" + String.format("%04d", (i + 101)))
                            .title(item.getTitle())
                            .status(i == 0 ? CaseStatus.UNDER_INVESTIGATION : CaseStatus.OPEN)
                            .priority(result.getRiskAssessment().getRiskLevel() == RiskLevel.CRITICAL ? CasePriority.CRITICAL : CasePriority.HIGH)
                            .createdAt(Instant.now().minusSeconds((i + 1) * 3600L))
                            .assignedAnalyst("SOC Tier-2 Analyst")
                            .analystNotes("Flagged by automated heuristics. " + result.getRiskAssessment().getExplanation())
                            .associatedMessageIds(List.of(message.getId()))
                            .analysisResultIds(List.of(result.getAnalysisId()))
                            .tags(List.of("SyntheticFixture", result.getRiskAssessment().getRiskLevel().name(), "AcademicDemo"))
                            .build();

                    caseRepository.saveCase(c);
                }
            } catch (Exception e) {
                log.warn("Failed to seed demo fixture: {}", e.getMessage());
            }
        }
        log.info("Seeding complete. Initialized {} demo threat scenarios.", fixtures.size());
    }
}

