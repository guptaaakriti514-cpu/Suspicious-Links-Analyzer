package com.mailshield.intelligence;

import com.mailshield.model.Finding;

import java.util.List;

/**
 * Service contract for querying reputation intelligence on domains, URLs, and attachment hashes.
 */
public interface ThreatIntelligenceService {

    /**
     * Query domain reputation.
     *
     * @param domain Domain to inspect
     * @return List of findings or empty list if benign/unknown
     */
    List<Finding> checkDomainReputation(String domain);

    /**
     * Query attachment hash reputation.
     *
     * @param sha256 SHA-256 hash
     * @param filename Filename for context
     * @return List of findings
     */
    List<Finding> checkHashReputation(String sha256, String filename);

    /**
     * Query URL reputation (only sanitized public domain/path without sensitive tokens).
     *
     * @param normalizedUrl Normalized URL
     * @return List of findings
     */
    List<Finding> checkUrlReputation(String normalizedUrl);

    /**
     * Human-readable provider name (e.g., "MailShield Local Intelligence Feeds (Sample / Offline Fixture)").
     */
    String getProviderName();

    /**
     * Whether this provider is operating offline in deterministic sample mode.
     */
    boolean isOfflineFixture();
}

