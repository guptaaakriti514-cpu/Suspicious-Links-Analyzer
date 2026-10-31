package com.mailshield.model;

public enum FindingType {
    HEURISTIC("Heuristic Indicator", "Rule-based structural or linguistic pattern matching"),
    PARSED_AUTHENTICATION_EVIDENCE("Parsed Authentication Evidence", "Extracted from message headers (SPF/DKIM/DMARC)"),
    EXTERNAL_INTELLIGENCE("External Threat Intelligence", "Corroborated reputation data from threat feeds"),
    METADATA_OBSERVATION("Metadata Observation", "Factual property observed in message envelope or attachments");

    private final String title;
    private final String explanation;

    FindingType(String title, String explanation) {
        this.title = title;
        this.explanation = explanation;
    }

    public String getTitle() {
        return title;
    }

    public String getExplanation() {
        return explanation;
    }
}

