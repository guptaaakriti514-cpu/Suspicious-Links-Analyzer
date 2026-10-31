package com.mailshield.scoring;

import com.mailshield.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class DefaultRiskScoringEngineTest {

    private DefaultRiskScoringEngine scoringEngine;

    @BeforeEach
    void setUp() {
        scoringEngine = new DefaultRiskScoringEngine();
    }

    @Test
    @DisplayName("Should return INSUFFICIENT_DATA when email has no headers or body")
    void testInsufficientData() {
        EmailMessage empty = EmailMessage.builder()
                .headers(List.of())
                .bodyText("")
                .bodyHtml("")
                .build();

        RiskAssessment assessment = scoringEngine.evaluateRisk(empty, List.of());
        assertThat(assessment.getRiskLevel()).isEqualTo(RiskLevel.INSUFFICIENT_DATA);
        assertThat(assessment.isInsufficientData()).isTrue();
    }

    @Test
    @DisplayName("Should evaluate clean legitimate email as LOW risk")
    void testCleanEmailLowRisk() {
        EmailMessage clean = EmailMessage.builder()
                .fromAddress("newsletter@company.com")
                .subject("Weekly Update")
                .bodyText("Here is your weekly update.")
                .headers(List.of(new EmailHeader("Message-ID", "<msg@co.com>")))
                .build();

        RiskAssessment assessment = scoringEngine.evaluateRisk(clean, List.of());
        assertThat(assessment.getRiskLevel()).isEqualTo(RiskLevel.LOW);
        assertThat(assessment.getScore()).isEqualTo(0);
    }

    @Test
    @DisplayName("Should cap score contribution per category to prevent correlated score inflation")
    void testCategoryCeilingCapping() {
        EmailMessage msg = EmailMessage.builder()
                .fromAddress("sender@domain.com")
                .bodyText("Urgent urgent urgent deadline action required immediately.")
                .headers(List.of(new EmailHeader("Message-ID", "<m@d.com>")))
                .build();

        // 6 duplicate social engineering findings
        List<Finding> duplicateFindings = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            duplicateFindings.add(Finding.builder()
                    .ruleId("SOC-00" + i)
                    .category(FindingCategory.SOCIAL_ENGINEERING)
                    .severity(Severity.HIGH) // 20 pts base * 0.9 = 18 pts each -> 108 raw pts
                    .confidence(0.9)
                    .build());
        }

        RiskAssessment assessment = scoringEngine.evaluateRisk(msg, duplicateFindings);
        // Social engineering category ceiling is capped at 30 pts!
        assertThat(assessment.getCategoryScores().get(FindingCategory.SOCIAL_ENGINEERING)).isLessThanOrEqualTo(30);
        assertThat(assessment.getScore()).isLessThanOrEqualTo(30);
        assertThat(assessment.getRiskLevel()).isEqualTo(RiskLevel.MEDIUM);
    }

    @Test
    @DisplayName("Critical severity finding must elevate risk score to at least Critical threshold")
    void testCriticalElevatesScore() {
        EmailMessage msg = EmailMessage.builder()
                .fromAddress("spoofed@paypal.com")
                .bodyText("Verify login.")
                .headers(List.of(new EmailHeader("Message-ID", "<m@d.com>")))
                .build();

        List<Finding> findings = List.of(
                Finding.builder()
                        .ruleId("ATT-001")
                        .category(FindingCategory.SUSPICIOUS_ATTACHMENT)
                        .severity(Severity.CRITICAL)
                        .confidence(0.95)
                        .shortDescription("Double extension executable")
                        .build()
        );

        RiskAssessment assessment = scoringEngine.evaluateRisk(msg, findings);
        assertThat(assessment.getRiskLevel()).isEqualTo(RiskLevel.CRITICAL);
        assertThat(assessment.getScore()).isGreaterThanOrEqualTo(80);
    }
}

