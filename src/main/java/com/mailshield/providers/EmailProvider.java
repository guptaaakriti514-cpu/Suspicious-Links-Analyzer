package com.mailshield.providers;

import com.mailshield.model.EmailMessage;
import com.mailshield.model.ProviderConnectionStatus;
import com.mailshield.model.ProviderType;

import java.util.List;

/**
 * Common interface for all email provider integrations.
 */
public interface EmailProvider {

    ProviderType getProviderType();

    ProviderConnectionStatus getStatus();

    default String getLastErrorMessage() {
        return getStatus() != null ? getStatus().getErrorMessage() : "";
    }

    /**
     * Test authentication and API connectivity.
     */
    boolean testConnection();

    /**
     * Connect or trigger OAuth authorization flow.
     */
    boolean authenticate();

    /**
     * Disconnect provider and revoke active credentials.
     */
    void disconnect();

    /**
     * Fetch recent emails up to the specified limit.
     * Normalizes each message into the standard EmailMessage domain model.
     *
     * @param maxMessages maximum number of messages to retrieve
     * @return normalized list of EmailMessages
     * @throws ProviderException on API or network failure
     */
    List<EmailMessage> fetchRecentMessages(int maxMessages) throws ProviderException;
}
