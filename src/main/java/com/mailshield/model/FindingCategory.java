package com.mailshield.model;

public enum FindingCategory {
    HEADER_ANOMALY("Header Anomaly", "Inconsistencies in RFC 5322 headers or transmission hops"),
    SPOOFING_IMPERSONATION("Spoofing & Impersonation", "Display name vs envelope mismatch or executive impersonation"),
    AUTHENTICATION_FAILURE("Authentication Failure", "Parsed SPF, DKIM, or DMARC authentication verdict"),
    SOCIAL_ENGINEERING("Social Engineering", "Urgency, threats, credential requests, or psychological pressure"),
    SUSPICIOUS_URL("Suspicious URL", "Homograph, deceptive anchor text, IP host, or dangerous redirection"),
    SUSPICIOUS_ATTACHMENT("Suspicious Attachment", "Double extensions, macro-enabled files, or executable payloads"),
    THREAT_INTELLIGENCE("Threat Intelligence", "Reputation match from threat databases or sample fixtures"),
    CONTENT_HEURISTIC("Content Heuristic", "Heuristic indicators in email body formatting or structure");

    private final String label;
    private final String description;

    FindingCategory(String label, String description) {
        this.label = label;
        this.description = description;
    }

    public String getLabel() {
        return label;
    }

    public String getDescription() {
        return description;
    }
}

