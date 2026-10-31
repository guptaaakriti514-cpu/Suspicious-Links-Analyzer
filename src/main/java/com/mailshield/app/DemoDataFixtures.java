package com.mailshield.app;

import com.mailshield.model.RiskLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Loads standard RFC 5322 training scenarios from resources on demand.
 * No mock data is stored directly in database or code constants.
 */
public final class DemoDataFixtures {

    private static final Logger log = LoggerFactory.getLogger(DemoDataFixtures.class);

    private DemoDataFixtures() {}

    private static String loadResource(String path) {
        try (InputStream is = DemoDataFixtures.class.getResourceAsStream(path)) {
            if (is == null) {
                log.warn("Training scenario file not found: {}", path);
                return "";
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("Failed to read scenario resource {}: {}", path, e.getMessage());
            return "";
        }
    }

    public static List<EmailFixtureItem> getAvailableFixtures() {
        List<EmailFixtureItem> list = new ArrayList<>();
        list.add(new EmailFixtureItem(
                "Scenario 1: Credential Harvesting Phish (PayPal Impersonation)",
                "Urgent suspension threat, deceptive homograph domain (paypa1), anchor text mismatch, IP host destination, SPF/DKIM failures.",
                RiskLevel.CRITICAL,
                loadResource("/training-scenarios/demo-01-paypal-phish.eml")
        ));
        list.add(new EmailFixtureItem(
                "Scenario 2: CEO Fraud / BEC (Business Email Compromise)",
                "Executive impersonation, urgent wire transfer request ($78.5k), secrecy demand, Reply-To directing to personal address.",
                RiskLevel.HIGH,
                loadResource("/training-scenarios/demo-02-ceo-fraud-bec.eml")
        ));
        list.add(new EmailFixtureItem(
                "Scenario 3: Suspicious Attachment (.pdf.exe)",
                "Remittance lure containing a double extension executable disguised as a PDF document.",
                RiskLevel.CRITICAL,
                loadResource("/training-scenarios/demo-03-malicious-attachment.eml")
        ));
        list.add(new EmailFixtureItem(
                "Scenario 4: Benign Legitimate Email (GitHub Digest)",
                "Authentic newsletter with SPF pass, DKIM pass, DMARC pass, matching HTTPS links, and normal RFC headers.",
                RiskLevel.LOW,
                loadResource("/training-scenarios/demo-04-benign-newsletter.eml")
        ));
        return Collections.unmodifiableList(list);
    }

    public static class EmailFixtureItem {
        private final String title;
        private final String description;
        private final RiskLevel expectedRisk;
        private final String rawContent;

        public EmailFixtureItem(String title, String description, RiskLevel expectedRisk, String rawContent) {
            this.title = title;
            this.description = description;
            this.expectedRisk = expectedRisk;
            this.rawContent = rawContent;
        }

        public String getTitle() { return title; }
        public String getDescription() { return description; }
        public RiskLevel getExpectedRisk() { return expectedRisk; }
        public String getRawContent() { return rawContent; }

        @Override
        public String toString() {
            return title + " [" + expectedRisk.getLabel() + "]";
        }
    }
}
