package com.mailshield.model;

public enum MonitoringState {
    NOT_CONFIGURED("Not Configured", "Inbox provider credentials not set"),
    RUNNING("Running", "Active background polling underway"),
    PAUSED("Paused", "Monitoring temporarily paused by user"),
    DISCONNECTED("Disconnected", "OAuth token revoked or disconnected"),
    ERROR("Error State", "Encountered network, quota, or auth error");

    private final String display;
    private final String description;

    MonitoringState(String display, String description) {
        this.display = display;
        this.description = description;
    }

    public String getDisplay() {
        return display;
    }

    public String getDescription() {
        return description;
    }
}

