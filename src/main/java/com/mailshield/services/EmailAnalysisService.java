package com.mailshield.services;

import com.mailshield.forensics.EvidenceManager;
import com.mailshield.model.*;
import com.mailshield.storage.CaseRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;

/**
 * Enterprise Email Analysis Pipeline Service.
 * Ingests raw parsed emails, executes deep multi-vector threat detection,
 * records verifiable digital evidence hashes, persists results into SQLite,
 * and publishes real-time security alerts.
 */
public class EmailAnalysisService {

    private static final Logger log = LoggerFactory.getLogger(EmailAnalysisService.class);

    private final ThreatDetectionService threatDetectionService;
    private final CaseRepository caseRepository;
    private final EvidenceManager evidenceManager;
    private final NotificationService notificationService;

    public EmailAnalysisService(ThreatDetectionService threatDetectionService,
                                CaseRepository caseRepository,
                                EvidenceManager evidenceManager,
                                NotificationService notificationService) {
        this.threatDetectionService = threatDetectionService;
        this.caseRepository = caseRepository;
        this.evidenceManager = evidenceManager;
        this.notificationService = notificationService;
    }

    /**
     * Executes the end-to-end analysis pipeline on an incoming email message.
     */
    public synchronized AnalysisResult processAndPersist(EmailMessage message) {
        if (message == null) {
            throw new IllegalArgumentException("Cannot process null email message.");
        }

        // 1. Execute threat detection pipeline
        AnalysisResult analysisResult = threatDetectionService.analyzeEmail(message);

        // 2. Register cryptographic forensic evidence
        try {
            if (evidenceManager != null) {
                evidenceManager.recordEvidence(message, null, "MailShield Ingestion Pipeline");
            }
        } catch (Exception e) {
            log.warn("Forensic evidence recording encountered non-fatal error: {}", e.getMessage());
        }

        // 3. Persist email and analysis results to SQLite
        try {
            if (caseRepository != null) {
                caseRepository.saveEmailMessage(message);
                caseRepository.saveAnalysisResult(analysisResult);
            }
        } catch (Exception e) {
            log.error("Failed to persist email analysis to repository: {}", e.getMessage(), e);
        }

        // 4. Trigger security alert if threat is severe
        RiskAssessment assessment = analysisResult.getRiskAssessment();
        RiskLevel level = assessment != null ? assessment.getRiskLevel() : RiskLevel.LOW;
        int score = assessment != null ? assessment.getScore() : 0;
        String explanation = assessment != null ? assessment.getExplanation() : "";

        if (level == RiskLevel.CRITICAL || level == RiskLevel.HIGH) {
            String title = (level == RiskLevel.CRITICAL ? "CRITICAL THREAT: " : "HIGH RISK: ") +
                    (message.getSubject() != null && !message.getSubject().isBlank() ? message.getSubject() : "Suspicious Message");
            String details = String.format("From: %s | Score: %d/100 | %s",
                    message.getFromAddress(), score, explanation);
            if (notificationService != null) {
                notificationService.publishAlert(title, details, level.name(), message.getId());
            }
        }

        log.info("Processed email ID={} From='{}' Score={} Level={}",
                message.getId(), message.getFromAddress(), score, level);

        return analysisResult;
    }

    public Optional<AnalysisResult> getAnalysis(String emailId) {
        return caseRepository != null ? caseRepository.findAnalysisResultByEmailId(emailId) : Optional.empty();
    }

    public Optional<EmailMessage> getEmail(String emailId) {
        return caseRepository != null ? caseRepository.findEmailMessageById(emailId) : Optional.empty();
    }

    public List<AnalysisResult> getRecentAnalyses(int limit) {
        return caseRepository != null ? caseRepository.findRecentAnalyses(limit) : List.of();
    }

    public List<EmailMessage> getRecentEmails(int limit) {
        return caseRepository != null ? caseRepository.findAllEmails(limit, 0) : List.of();
    }

    public int getTotalEmailsAnalyzed() {
        return caseRepository != null ? caseRepository.getTotalEmailCount() : 0;
    }
}
