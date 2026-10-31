package com.mailshield.model;

import java.time.Instant;

/**
 * Live status for automated background inbox monitoring.
 */
public final class MonitoringStatus {
    private final MonitoringState state;
    private final Instant lastPollTime;
    private final int pollIntervalSeconds;
    private final int messagesProcessedCount;
    private final String lastError;
    private final ProviderType activeProvider;

    public MonitoringStatus(MonitoringState state, Instant lastPollTime, int pollIntervalSeconds,
                            int messagesProcessedCount, String lastError, ProviderType activeProvider) {
        this.state = state != null ? state : MonitoringState.NOT_CONFIGURED;
        this.lastPollTime = lastPollTime;
        this.pollIntervalSeconds = pollIntervalSeconds;
        this.messagesProcessedCount = messagesProcessedCount;
        this.lastError = lastError != null ? lastError : "";
        this.activeProvider = activeProvider != null ? activeProvider : ProviderType.MANUAL_PASTE;
    }

    public static MonitoringStatus notConfigured() {
        return new MonitoringStatus(MonitoringState.NOT_CONFIGURED, null, 60, 0,
                "No cloud email inboxes configured for continuous monitoring.", ProviderType.MANUAL_PASTE);
    }

    public MonitoringState getState() {
        return state;
    }

    public Instant getLastPollTime() {
        return lastPollTime;
    }

    public int getPollIntervalSeconds() {
        return pollIntervalSeconds;
    }

    public int getMessagesProcessedCount() {
        return messagesProcessedCount;
    }

    public String getLastError() {
        return lastError;
    }

    public ProviderType getActiveProvider() {
        return activeProvider;
    }
}

