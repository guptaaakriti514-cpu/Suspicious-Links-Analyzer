package com.mailshield.model;

/**
 * Overall risk classification level for an analyzed email.
 */
public enum RiskLevel {
    INSUFFICIENT_DATA("Insufficient Data", "#6c757d", 0),
    LOW("Low Risk", "#28a745", 25),
    MEDIUM("Medium Risk", "#ffc107", 50),
    HIGH("High Risk", "#fd7e14", 75),
    CRITICAL("Critical Threat", "#dc3545", 100);

    private final String label;
    private final String hexColor;
    private final int baselineScore;

    RiskLevel(String label, String hexColor, int baselineScore) {
        this.label = label;
        this.hexColor = hexColor;
        this.baselineScore = baselineScore;
    }

    public String getLabel() {
        return label;
    }

    public String getHexColor() {
        return hexColor;
    }

    public int getBaselineScore() {
        return baselineScore;
    }
}

