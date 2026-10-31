package com.mailshield.ingestion;

import com.mailshield.detection.SafeUrlAnalyzer;
import com.mailshield.model.AuthenticationResult;
import com.mailshield.model.EmailMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

public class SafeEmailParserTest {

    private SafeEmailParser parser;

    @BeforeEach
    void setUp() {
        parser = new SafeEmailParser(new SafeUrlAnalyzer());
    }

    private String readScenario(String resourcePath) throws Exception {
        try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
            assertThat(is).isNotNull();
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    @DisplayName("Should successfully parse raw RFC 5322 email text")
    void testParseRawText() throws Exception {
        String raw = readScenario("/training-scenarios/demo-01-paypal-phish.eml");
        EmailMessage message = parser.parseRawText(raw);

        assertThat(message).isNotNull();
        assertThat(message.getSubject()).contains("Your PayPal Account Will Be Suspended");
        assertThat(message.getFromAddress()).isEqualTo("security-alert@paypa1-account-security.net");
        assertThat(message.getFromDisplayName()).isEqualTo("PayPal Security Support");
        assertThat(message.getReplyTo()).isEqualTo("support-collector@temp-relay-mail.top");
        assertThat(message.getReturnPath()).isEqualTo("bounce-daemon@temp-relay-mail.top");
        assertThat(message.getRawSha256()).isNotEmpty();

        // Check extracted URLs
        assertThat(message.getExtractedUrls()).isNotEmpty();
        assertThat(message.getExtractedUrls()).anyMatch(u -> u.isMismatchWithAnchor() || u.isIpHost());

        // Check parsed Authentication-Results
        AuthenticationResult auth = message.getAuthResult();
        assertThat(auth.isHasAuthenticationHeader()).isTrue();
        assertThat(auth.getSpfStatus()).isEqualTo(AuthenticationResult.AuthStatus.FAIL);
        assertThat(auth.getDkimStatus()).isEqualTo(AuthenticationResult.AuthStatus.FAIL);
        assertThat(auth.getDmarcStatus()).isEqualTo(AuthenticationResult.AuthStatus.FAIL);
    }

    @Test
    @DisplayName("Should safely parse multipart attachment metadata without executing content")
    void testParseAttachmentMetadata() throws Exception {
        try (InputStream is = getClass().getResourceAsStream("/training-scenarios/demo-03-malicious-attachment.eml")) {
            assertThat(is).isNotNull();
            EmailMessage message = parser.parseEmlStream(is, "sample.eml");

            assertThat(message).isNotNull();
            assertThat(message.getAttachments()).hasSize(1);
            var att = message.getAttachments().get(0);
            assertThat(att.getFilename()).isEqualTo("Invoice_Sept2026_Final.pdf.exe");
            assertThat(att.getSha256Hash()).isNotEmpty();
        }
    }

    @Test
    @DisplayName("Should fallback gracefully when parsing malformed email without boundaries")
    void testFallbackMalformedParsing() throws Exception {
        String malformed = "From: Alice <alice@example.com>\nSubject: Quick Question\n\nHey Bob, are you free?";
        EmailMessage message = parser.parseRawText(malformed);

        assertThat(message).isNotNull();
        assertThat(message.getFromAddress()).isEqualTo("alice@example.com");
        assertThat(message.getSubject()).isEqualTo("Quick Question");
        assertThat(message.getBodyText()).contains("Hey Bob, are you free?");
    }
}
