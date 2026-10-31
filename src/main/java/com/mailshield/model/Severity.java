package com.mailshield.model;

/**
 * Severity rating for an individual detection finding.
 */
public enum Severity {
    INFO(0, "Informational"),
    LOW(1, "Low Risk"),
    MEDIUM(2, "Medium Risk"),
    HIGH(3, "High Risk"),
    CRITICAL(4, "Critical Threat");

    private final int rank;
    private final String displayName;

    Severity(int rank, String displayName) {
        this.rank = rank;
        this.displayName = displayName;
    }

    public int getRank() {
        return rank;
    }

    public String getDisplayName() {
        return displayName;
    }
}

