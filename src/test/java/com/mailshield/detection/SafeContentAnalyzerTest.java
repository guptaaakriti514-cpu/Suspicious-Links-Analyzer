package com.mailshield.detection;

import com.mailshield.model.EmailMessage;
import com.mailshield.model.Finding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class SafeContentAnalyzerTest {

    private SafeContentAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new SafeContentAnalyzer();
    }

    @Test
    @DisplayName("Should detect Urgency + Account Suspension compound phishing pattern")
    void testUrgencyAndSuspensionThreat() {
        EmailMessage msg = EmailMessage.builder()
                .subject("URGENT: Your account will be suspended within 24 hours")
                .bodyText("Dear Customer, we detected unauthorized activity. Verify your identity immediately or your account will be suspended.")
                .build();

        List<Finding> findings = analyzer.analyzeContent(msg);
        assertThat(findings).anyMatch(f -> f.getRuleId().equals("SOC-001"));
    }

    @Test
    @DisplayName("Should detect Business Email Compromise (BEC) CEO wire transfer pattern")
    void testBecWireFraudPattern() {
        EmailMessage msg = EmailMessage.builder()
                .subject("STRICTLY CONFIDENTIAL: Wire Transfer Request")
                .bodyText("I am currently in a meeting and cannot take calls. Please execute an urgent wire transfer to the escrow account before 2 PM.")
                .build();

        List<Finding> findings = analyzer.analyzeContent(msg);
        assertThat(findings).anyMatch(f -> f.getRuleId().equals("SOC-003"));
    }

    @Test
    @DisplayName("Should not flag benign corporate communication")
    void testBenignCorporateCommunication() {
        EmailMessage msg = EmailMessage.builder()
                .subject("Team Lunch on Friday")
                .bodyText("Hi team, please let me know your dietary preferences by Thursday so we can reserve tables.")
                .build();

        List<Finding> findings = analyzer.analyzeContent(msg);
        assertThat(findings).isEmpty();
    }
}

