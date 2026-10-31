package com.mailshield.model;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

/**
 * Live status for cloud email provider connections (Gmail API, Microsoft Graph).
 */
public final class ProviderConnectionStatus {
    private final ProviderType providerType;
    private final boolean isConnected;
    private final String accountEmail;
    private final Instant lastSyncTime;
    private final String syncStatus;
    private final String errorMessage;
    private final List<String> scopesGranted;
    private final boolean isConfigured;

    public ProviderConnectionStatus(ProviderType providerType, boolean isConnected,
                                    String accountEmail, Instant lastSyncTime, String syncStatus,
                                    String errorMessage, List<String> scopesGranted, boolean isConfigured) {
        this.providerType = providerType;
        this.isConnected = isConnected;
        this.accountEmail = accountEmail != null ? accountEmail : "";
        this.lastSyncTime = lastSyncTime;
        this.syncStatus = syncStatus != null ? syncStatus : "Idle";
        this.errorMessage = errorMessage != null ? errorMessage : "";
        this.scopesGranted = scopesGranted != null ? Collections.unmodifiableList(scopesGranted) : Collections.emptyList();
        this.isConfigured = isConfigured;
    }

    public static ProviderConnectionStatus notConfigured(ProviderType type) {
        return new ProviderConnectionStatus(type, false, "Not Registered", null,
                "Awaiting Client ID & Secret configuration", "", Collections.emptyList(), false);
    }

    public static ProviderConnectionStatus disconnected(ProviderType type, String accountEmail) {
        return new ProviderConnectionStatus(type, false, accountEmail, null,
                "Disconnected / Authorization Required", "", Collections.emptyList(), true);
    }

    public ProviderType getProviderType() {
        return providerType;
    }

    public boolean isConnected() {
        return isConnected;
    }

    public String getAccountEmail() {
        return accountEmail;
    }

    public Instant getLastSyncTime() {
        return lastSyncTime;
    }

    public String getSyncStatus() {
        return syncStatus;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public List<String> getScopesGranted() {
        return scopesGranted;
    }

    public boolean isConfigured() {
        return isConfigured;
    }
}

