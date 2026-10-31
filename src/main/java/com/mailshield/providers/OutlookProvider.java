package com.mailshield.providers;

/**
 * Interface for official Microsoft Graph API / Outlook 365 integration.
 */
public interface OutlookProvider extends EmailProvider {
    void setCredentials(String clientId, String tenantId);
    boolean hasStoredCredentials();
}

