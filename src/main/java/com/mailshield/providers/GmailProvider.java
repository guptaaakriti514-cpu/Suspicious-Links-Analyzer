package com.mailshield.providers;

/**
 * Interface for official Google Gmail API integration.
 */
public interface GmailProvider extends EmailProvider {
    void setCredentials(String clientId, String clientSecret, int redirectPort);
    boolean hasStoredCredentials();
}

