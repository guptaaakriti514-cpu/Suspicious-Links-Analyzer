package com.mailshield.app;

import com.mailshield.model.*;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Deterministic synthetic demo fixtures for academic presentation, testing, and offline demonstration.
 * All fixtures are completely synthetic and contain no real user data, private tokens, or real malware.
 */
public final class DemoDataFixtures {

    private DemoDataFixtures() {}

    public static final String RAW_PAYPAL_PHISH_EML =
        "From: \"PayPal Security Support\" <security-alert@paypa1-account-security.net>\r\n" +
        "Reply-To: support-collector@temp-relay-mail.top\r\n" +
        "To: victim.employee@target-corp.com\r\n" +
        "Subject: [URGENT] Your PayPal Account Will Be Suspended Within 24 Hours - Action Required\r\n" +
        "Date: Wed, 28 Oct 2026 14:15:20 +0530\r\n" +
        "Message-ID: <20261028141520.98421.alert@paypa1-account-security.net>\r\n" +
        "Return-Path: <bounce-daemon@temp-relay-mail.top>\r\n" +
        "Authentication-Results: mx.target-corp.com; spf=fail (sender IP 198.51.100.22) smtp.mailfrom=bounce-daemon@temp-relay-mail.top; dkim=fail header.d=paypa1-account-security.net; dmarc=fail action=none header.from=paypa1-account-security.net\r\n" +
        "Received: from relay02.temp-relay-mail.top (relay02.temp-relay-mail.top [198.51.100.22]) by mx.target-corp.com with ESMTP id p44321; Wed, 28 Oct 2026 14:15:22 +0530\r\n" +
        "Content-Type: text/html; charset=UTF-8\r\n" +
        "MIME-Version: 1.0\r\n" +
        "\r\n" +
        "<html><body>\r\n" +
        "<div style='font-family: Arial, sans-serif;'>\r\n" +
        "<h2 style='color: #c00;'>Critical Security Notice: Suspicious Login Detected</h2>\r\n" +
        "<p>Dear Valued Customer,</p>\r\n" +
        "<p>We have detected unauthorized sign-in attempts to your PayPal business account from an unknown device in Moscow, Russia.</p>\r\n" +
        "<p>To protect your account funds and prevent permanent account termination, you must verify your identity and update your credentials immediately.</p>\r\n" +
        "<p>Failure to verify your identity within <strong>24 hours</strong> will result in permanent account suspension and frozen funds.</p>\r\n" +
        "<p><a href='http://198.51.100.55/login/verify-identity.php' style='background:#0070ba;color:#fff;padding:10px 20px;text-decoration:none;'>Log In to Verify Account</a></p>\r\n" +
        "<p>Or visit: <a href='http://198.51.100.55/login/verify-identity.php'>https://www.paypal.com/security/verify-account</a></p>\r\n" +
        "<br/><p>Sincerely,<br/>PayPal Account Risk & Anti-Fraud Department</p>\r\n" +
        "</div></body></html>";

    public static final String RAW_CEO_FRAUD_BEC_EML =
        "From: \"Robert Sterling, Chief Executive Officer\" <ceo.robert.sterling@external-partner-consulting.com>\r\n" +
        "Reply-To: executive.board.directive77@gmail.com\r\n" +
        "To: junior.finance@target-corp.com\r\n" +
        "Subject: STRICTLY CONFIDENTIAL: Urgent Vendor Acquisition Settlement Wire Transfer\r\n" +
        "Date: Wed, 28 Oct 2026 09:30:15 +0530\r\n" +
        "Message-ID: <BEC-20261028-093015@exec-directive.internal>\r\n" +
        "Return-Path: <exec-directive@bounce-mail.net>\r\n" +
        "Authentication-Results: mx.target-corp.com; spf=softfail (sender IP 203.0.113.88); dkim=none; dmarc=none\r\n" +
        "Content-Type: text/plain; charset=UTF-8\r\n" +
        "\r\n" +
        "Hello,\r\n\r\n" +
        "I am currently in an all-day executive board meeting with our merger & acquisition attorneys and cannot take voice calls.\r\n\r\n" +
        "We are closing a confidential strategic acquisition this afternoon. I need you to immediately execute an urgent outbound wire transfer of $78,500.00 to the escrow account provided below before 2:00 PM EST.\r\n\r\n" +
        "Do not discuss this with anyone in the office yet as NDAs are strictly enforced. Reply directly to this email as soon as you are at your desk and I will send the bank wire routing coordinates.\r\n\r\n" +
        "Best regards,\r\n" +
        "Robert Sterling\r\n" +
        "CEO & Executive Chairman\r\n" +
        "Target Corp";

    public static final String RAW_MALICIOUS_ATTACHMENT_EML =
        "From: \"Accounts Payable Dispatch\" <billing-department@global-invoicing-portal.com>\r\n" +
        "Reply-To: billing-department@global-invoicing-portal.com\r\n" +
        "To: accounts@target-corp.com\r\n" +
        "Subject: Overdue Notice: Outstanding Remittance Advice INV-2026-9081\r\n" +
        "Date: Tue, 27 Oct 2026 16:45:00 +0530\r\n" +
        "Message-ID: <INV-9081-ATTACH@global-invoicing-portal.com>\r\n" +
        "Content-Type: multipart/mixed; boundary=\"====BOUNDARY_ATTACH_DEMO====\"\r\n" +
        "MIME-Version: 1.0\r\n" +
        "\r\n" +
        "--====BOUNDARY_ATTACH_DEMO====\r\n" +
        "Content-Type: text/plain; charset=UTF-8\r\n" +
        "\r\n" +
        "Please find attached your overdue remittance summary for September 2026.\r\n" +
        "Please open the attached PDF report immediately to reconcile penalty fees.\r\n" +
        "\r\n" +
        "--====BOUNDARY_ATTACH_DEMO====\r\n" +
        "Content-Type: application/octet-stream; name=\"Invoice_Sept2026_Final.pdf.exe\"\r\n" +
        "Content-Disposition: attachment; filename=\"Invoice_Sept2026_Final.pdf.exe\"\r\n" +
        "Content-Transfer-Encoding: base64\r\n" +
        "\r\n" +
        "TVpQAAIAAAAEAA8A//8AALgAAAAAAAAAQAAaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n" +
        "--====BOUNDARY_ATTACH_DEMO====--";

    public static final String RAW_BENIGN_NEWSLETTER_EML =
        "From: \"GitHub Security Lab\" <notifications@github.com>\r\n" +
        "Reply-To: support@github.com\r\n" +
        "To: developer@target-corp.com\r\n" +
        "Subject: GitHub Security Advisory: Monthly Open Source Security Roundup\r\n" +
        "Date: Mon, 26 Oct 2026 11:00:00 +0530\r\n" +
        "Message-ID: <gh-advisory-20261026@github.com>\r\n" +
        "Return-Path: <bounces@github.com>\r\n" +
        "Authentication-Results: mx.target-corp.com; spf=pass (sender IP 140.82.112.4) smtp.mailfrom=bounces@github.com; dkim=pass header.d=github.com; dmarc=pass action=none header.from=github.com\r\n" +
        "Content-Type: text/html; charset=UTF-8\r\n" +
        "\r\n" +
        "<html><body>\r\n" +
        "<div style='font-family: sans-serif;'>\r\n" +
        "<h3>GitHub Security Lab Digest</h3>\r\n" +
        "<p>Welcome to our monthly community roundup covering best practices for securing supply chains in modern CI/CD pipelines.</p>\r\n" +
        "<p>Read the complete technical research on our blog: <a href='https://github.blog/security'>https://github.blog/security</a></p>\r\n" +
        "<p>You are receiving this digest because you subscribed to GitHub Security Advisories. <a href='https://github.com/settings/notifications'>Unsubscribe</a></p>\r\n" +
        "</div></body></html>";

    public static List<EmailFixtureItem> getAvailableFixtures() {
        return List.of(
            new EmailFixtureItem(
                "DEMO-01: Critical Credential Harvesting Phish (PayPal Impersonation)",
                "Urgent account suspension threat, deceptive homograph domain (paypa1), anchor text mismatch, IP host destination, SPF/DKIM authentication failures.",
                RiskLevel.CRITICAL,
                RAW_PAYPAL_PHISH_EML
            ),
            new EmailFixtureItem(
                "DEMO-02: High-Risk CEO Fraud / BEC (Business Email Compromise)",
                "Executive impersonation, urgent wire transfer request ($78.5k), secrecy/NDA demand, Reply-To directing to personal Gmail address.",
                RiskLevel.HIGH,
                RAW_CEO_FRAUD_BEC_EML
            ),
            new EmailFixtureItem(
                "DEMO-03: Malicious Attachment (Double Extension .pdf.exe)",
                "Fake overdue invoice lure containing a deceptive executable disguised as a PDF document (Invoice_Sept2026_Final.pdf.exe).",
                RiskLevel.CRITICAL,
                RAW_MALICIOUS_ATTACHMENT_EML
            ),
            new EmailFixtureItem(
                "DEMO-04: Benign Legitimate Email (GitHub Security Lab)",
                "Authentic newsletter with SPF pass, DKIM pass, DMARC pass, matching HTTPS links, and no social engineering pressure.",
                RiskLevel.LOW,
                RAW_BENIGN_NEWSLETTER_EML
            )
        );
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

