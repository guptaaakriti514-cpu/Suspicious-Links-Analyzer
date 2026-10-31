package com.mailshield.detection;

import com.mailshield.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class SafeHeaderAnalyzerTest {

    private SafeHeaderAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new SafeHeaderAnalyzer();
    }

    @Test
    @DisplayName("Should detect From and Reply-To domain divergence")
    void testFromReplyToMismatch() {
        EmailMessage msg = EmailMessage.builder()
                .from("security@paypal.com")
                .fromAddress("security@paypal.com")
                .replyTo("attacker@disposable-mail.net")
                .headers(List.of(
                        new EmailHeader("From", "security@paypal.com"),
                        new EmailHeader("Reply-To", "attacker@disposable-mail.net"),
                        new EmailHeader("Message-ID", "<123@paypal.com>")
                ))
                .build();

        List<Finding> findings = analyzer.analyzeHeaders(msg);
        assertThat(findings).anyMatch(f -> f.getRuleId().equals("HDR-001"));
    }

    @Test
    @DisplayName("Should detect Display Name brand spoofing")
    void testDisplayNameBrandSpoofing() {
        EmailMessage msg = EmailMessage.builder()
                .fromDisplayName("PayPal Security Center")
                .fromAddress("support@unrelated-hacker-domain.xyz")
                .headers(List.of(new EmailHeader("Message-ID", "<abc@domain.xyz>")))
                .build();

        List<Finding> findings = analyzer.analyzeHeaders(msg);
        assertThat(findings).anyMatch(f -> f.getRuleId().equals("HDR-002"));
    }

    @Test
    @DisplayName("Should parse SPF and DKIM authentication failures")
    void testAuthenticationFailures() {
        AuthenticationResult auth = new AuthenticationResult(
                AuthenticationResult.AuthStatus.FAIL, "sender@evil.com",
                AuthenticationResult.AuthStatus.FAIL, "evil.com",
                AuthenticationResult.AuthStatus.FAIL, "reject",
                "spf=fail; dkim=fail; dmarc=fail", true
        );

        EmailMessage msg = EmailMessage.builder()
                .fromAddress("sender@company.com")
                .authResult(auth)
                .headers(List.of(new EmailHeader("Message-ID", "<msg-1@company.com>")))
                .build();

        List<Finding> findings = analyzer.analyzeHeaders(msg);
        assertThat(findings).anyMatch(f -> f.getRuleId().equals("AUTH-002")); // SPF fail
        assertThat(findings).anyMatch(f -> f.getRuleId().equals("AUTH-004")); // DKIM fail
        assertThat(findings).anyMatch(f -> f.getRuleId().equals("AUTH-005")); // DMARC fail
    }

    @Test
    @DisplayName("Should distinguish missing authentication header without false failure")
    void testMissingAuthHeader() {
        EmailMessage msg = EmailMessage.builder()
                .fromAddress("user@internal.lan")
                .authResult(AuthenticationResult.missing())
                .headers(List.of(new EmailHeader("Message-ID", "<internal-01@lan>")))
                .build();

        List<Finding> findings = analyzer.analyzeHeaders(msg);
        // Should report informational missing status (AUTH-001), NOT authentication failure
        assertThat(findings).anyMatch(f -> f.getRuleId().equals("AUTH-001") && f.getSeverity() == Severity.INFO);
        assertThat(findings).noneMatch(f -> f.getRuleId().equals("AUTH-002"));
    }
}

