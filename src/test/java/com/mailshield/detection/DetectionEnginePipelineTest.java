package com.mailshield.detection;

import com.mailshield.ingestion.EmailParser;
import com.mailshield.ingestion.SafeEmailParser;
import com.mailshield.intelligence.LocalThreatIntelligenceService;
import com.mailshield.model.AnalysisResult;
import com.mailshield.model.EmailMessage;
import com.mailshield.model.RiskLevel;
import com.mailshield.scoring.DefaultRiskScoringEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

public class DetectionEnginePipelineTest {

    private DetectionEngine detectionEngine;
    private EmailParser emailParser;

    @BeforeEach
    void setUp() {
        SafeUrlAnalyzer urlAnalyzer = new SafeUrlAnalyzer();
        emailParser = new SafeEmailParser(urlAnalyzer);
        detectionEngine = new DetectionEngine(
                new SafeHeaderAnalyzer(),
                new SafeContentAnalyzer(),
                urlAnalyzer,
                new SafeAttachmentAnalyzer(),
                new LocalThreatIntelligenceService(),
                new DefaultRiskScoringEngine()
        );
    }

    private String readScenario(String resourcePath) throws Exception {
        try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
            assertThat(is).isNotNull();
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    @DisplayName("Scenario 1: Critical Credential Harvesting Phish must score CRITICAL")
    void testScenario1PayPalPhish() throws Exception {
        String rawEml = readScenario("/training-scenarios/demo-01-paypal-phish.eml");
        EmailMessage message = emailParser.parseRawText(rawEml);
        AnalysisResult result = detectionEngine.analyzeEmail(message);

        assertThat(result.getRiskAssessment().getRiskLevel()).isEqualTo(RiskLevel.CRITICAL);
        assertThat(result.getRiskAssessment().getScore()).isGreaterThanOrEqualTo(80);
        assertThat(result.getFindings()).anyMatch(f -> f.getRuleId().equals("SOC-001")); // Urgency + Suspension
        assertThat(result.getFindings()).anyMatch(f -> f.getRuleId().equals("HDR-001") || f.getRuleId().equals("HDR-002")); // Spoofing/Mismatch
    }

    @Test
    @DisplayName("Scenario 2: CEO Fraud / BEC Wire Request must score HIGH")
    void testScenario2CeoFraud() throws Exception {
        String rawEml = readScenario("/training-scenarios/demo-02-ceo-fraud-bec.eml");
        EmailMessage message = emailParser.parseRawText(rawEml);
        AnalysisResult result = detectionEngine.analyzeEmail(message);

        assertThat(result.getRiskAssessment().getRiskLevel()).isIn(RiskLevel.HIGH, RiskLevel.CRITICAL);
        assertThat(result.getRiskAssessment().getScore()).isGreaterThanOrEqualTo(55);
        assertThat(result.getFindings()).anyMatch(f -> f.getRuleId().equals("SOC-003")); // Wire Transfer BEC
    }

    @Test
    @DisplayName("Scenario 3: Disguised Double Extension Attachment must score CRITICAL")
    void testScenario3MaliciousAttachment() throws Exception {
        String rawEml = readScenario("/training-scenarios/demo-03-malicious-attachment.eml");
        EmailMessage message = emailParser.parseRawText(rawEml);
        AnalysisResult result = detectionEngine.analyzeEmail(message);

        assertThat(result.getRiskAssessment().getRiskLevel()).isEqualTo(RiskLevel.CRITICAL);
        assertThat(result.getRiskAssessment().getScore()).isGreaterThanOrEqualTo(80);
        assertThat(result.getFindings()).anyMatch(f -> f.getRuleId().equals("ATT-001")); // Double extension
    }

    @Test
    @DisplayName("Scenario 4: Benign Legitimate Email must score LOW")
    void testScenario4BenignNewsletter() throws Exception {
        String rawEml = readScenario("/training-scenarios/demo-04-benign-newsletter.eml");
        EmailMessage message = emailParser.parseRawText(rawEml);
        AnalysisResult result = detectionEngine.analyzeEmail(message);

        assertThat(result.getRiskAssessment().getRiskLevel()).isEqualTo(RiskLevel.LOW);
        assertThat(result.getRiskAssessment().getScore()).isLessThan(25);
    }
}
