package com.mailshield.model;

public enum CaseStatus {
    OPEN("Open"),
    UNDER_INVESTIGATION("Under Investigation"),
    RESOLVED("Resolved - Benign"),
    ESCALATED("Escalated - Confirmed Threat"),
    CLOSED("Closed");

    private final String display;

    CaseStatus(String display) {
        this.display = display;
    }

    public String getDisplay() {
        return display;
    }
}

