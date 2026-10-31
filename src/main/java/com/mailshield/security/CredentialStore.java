package com.mailshield.security;

import java.util.Optional;

/**
 * Service contract for secure credential and token persistence.
 */
public interface CredentialStore {

    void saveSecret(String key, String secret);

    Optional<String> getSecret(String key);

    void removeSecret(String key);

    boolean hasSecret(String key);
}

