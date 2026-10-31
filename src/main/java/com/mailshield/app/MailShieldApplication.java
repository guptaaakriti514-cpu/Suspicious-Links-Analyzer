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

            // 5. Zero-mock clean startup: Database starts empty and reflects only real user analyses
            log.info("Initialized MailShield repository and detection engines with clean empty state.");

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
}

