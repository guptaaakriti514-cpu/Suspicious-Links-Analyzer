package com.mailshield.detection;

import com.mailshield.app.DemoDataFixtures;
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

    @Test
    @DisplayName("Fixture 1: Critical Credential Harvesting Phish must score CRITICAL")
    void testFixture1PayPalPhish() throws Exception {
        EmailMessage message = emailParser.parseRawText(DemoDataFixtures.RAW_PAYPAL_PHISH_EML);
        AnalysisResult result = detectionEngine.analyzeEmail(message);

        assertThat(result.getRiskAssessment().getRiskLevel()).isEqualTo(RiskLevel.CRITICAL);
        assertThat(result.getRiskAssessment().getScore()).isGreaterThanOrEqualTo(80);
        assertThat(result.getFindings()).anyMatch(f -> f.getRuleId().equals("SOC-001")); // Urgency + Suspension
        assertThat(result.getFindings()).anyMatch(f -> f.getRuleId().equals("HDR-001") || f.getRuleId().equals("HDR-002")); // Spoofing/Mismatch
    }

    @Test
    @DisplayName("Fixture 2: CEO Fraud / BEC Wire Request must score HIGH")
    void testFixture2CeoFraud() throws Exception {
        EmailMessage message = emailParser.parseRawText(DemoDataFixtures.RAW_CEO_FRAUD_BEC_EML);
        AnalysisResult result = detectionEngine.analyzeEmail(message);

        assertThat(result.getRiskAssessment().getRiskLevel()).isIn(RiskLevel.HIGH, RiskLevel.CRITICAL);
        assertThat(result.getRiskAssessment().getScore()).isGreaterThanOrEqualTo(55);
        assertThat(result.getFindings()).anyMatch(f -> f.getRuleId().equals("SOC-003")); // Wire Transfer BEC
    }

    @Test
    @DisplayName("Fixture 3: Disguised Double Extension Attachment must score CRITICAL")
    void testFixture3MaliciousAttachment() throws Exception {
        EmailMessage message = emailParser.parseRawText(DemoDataFixtures.RAW_MALICIOUS_ATTACHMENT_EML);
        AnalysisResult result = detectionEngine.analyzeEmail(message);

        assertThat(result.getRiskAssessment().getRiskLevel()).isEqualTo(RiskLevel.CRITICAL);
        assertThat(result.getRiskAssessment().getScore()).isGreaterThanOrEqualTo(80);
        assertThat(result.getFindings()).anyMatch(f -> f.getRuleId().equals("ATT-001")); // Double extension
    }

    @Test
    @DisplayName("Fixture 4: Benign Legitimate Email must score LOW")
    void testFixture4BenignNewsletter() throws Exception {
        EmailMessage message = emailParser.parseRawText(DemoDataFixtures.RAW_BENIGN_NEWSLETTER_EML);
        AnalysisResult result = detectionEngine.analyzeEmail(message);

        assertThat(result.getRiskAssessment().getRiskLevel()).isEqualTo(RiskLevel.LOW);
        assertThat(result.getRiskAssessment().getScore()).isLessThan(25);
    }
}

