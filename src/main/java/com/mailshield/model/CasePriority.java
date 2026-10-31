package com.mailshield.model;

public enum CasePriority {
    LOW("Low"),
    MEDIUM("Medium"),
    HIGH("High"),
    CRITICAL("Critical");

    private final String label;

    CasePriority(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}

