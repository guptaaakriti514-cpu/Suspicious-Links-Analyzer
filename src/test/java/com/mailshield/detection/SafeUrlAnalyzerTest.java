package com.mailshield.detection;

import com.mailshield.model.ExtractedUrl;
import com.mailshield.model.Finding;
import com.mailshield.model.FindingCategory;
import com.mailshield.model.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class SafeUrlAnalyzerTest {

    private SafeUrlAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new SafeUrlAnalyzer();
    }

    @Test
    @DisplayName("Should detect bare IP host destination")
    void testBareIpHostDetection() {
        ExtractedUrl url = analyzer.inspectUrl("http://198.51.100.55/login/verify.php", "Verify Account");
        assertThat(url.isIpHost()).isTrue();
        assertThat(url.isSuspicious()).isTrue();
        assertThat(url.getSuspiciousReasons()).anyMatch(r -> r.contains("bare numerical IP address"));
    }

    @Test
    @DisplayName("Should detect deceptive anchor text mismatch")
    void testAnchorTextMismatch() {
        // Visible text claims to be PayPal, but hyperlink points to an external server
        ExtractedUrl url = analyzer.inspectUrl("http://198.51.100.55/auth", "https://www.paypal.com/signin");
        assertThat(url.isMismatchWithAnchor()).isTrue();
        assertThat(url.isSuspicious()).isTrue();
        assertThat(url.getSuspiciousReasons()).anyMatch(r -> r.contains("Deceptive link text"));
    }

    @Test
    @DisplayName("Should detect brand typosquatting / homographs")
    void testBrandTyposquatting() {
        ExtractedUrl url = analyzer.inspectUrl("https://paypa1-security-verification.com/login", "Log In");
        assertThat(url.hasHomograph()).isTrue();
        assertThat(url.isSuspicious()).isTrue();
    }

    @Test
    @DisplayName("Should detect URL shorteners")
    void testUrlShortener() {
        ExtractedUrl url = analyzer.inspectUrl("https://bit.ly/3xSecAlert", "Click Here");
        assertThat(url.isShortened()).isTrue();
        assertThat(url.isSuspicious()).isTrue();
    }

    @Test
    @DisplayName("Should detect obfuscated user-info in URL")
    void testUserInfoInUrl() {
        ExtractedUrl url = analyzer.inspectUrl("https://paypal.com@evil-attacker.com/steal", "PayPal Account");
        assertThat(url.hasUserInfo()).isTrue();
        assertThat(url.isSuspicious()).isTrue();
    }

    @Test
    @DisplayName("Should pass legitimate URLs without false positives")
    void testLegitimateUrl() {
        ExtractedUrl url = analyzer.inspectUrl("https://github.com/torvalds/linux", "https://github.com/torvalds/linux");
        assertThat(url.isIpHost()).isFalse();
        assertThat(url.isMismatchWithAnchor()).isFalse();
        assertThat(url.hasHomograph()).isFalse();
        assertThat(url.isShortened()).isFalse();
        assertThat(url.isSuspicious()).isFalse();
    }
}

