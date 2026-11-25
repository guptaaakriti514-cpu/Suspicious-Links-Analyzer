package com.mailshield.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.Optional;
import java.util.Properties;

/**
 * Enterprise credential store for OAuth tokens and API secrets.
 * Backed by AES-256-GCM authenticated encryption at rest via TokenManagementService.
 * Never logs secrets or tokens in plaintext.
 */
public class DefaultCredentialStore implements CredentialStore {

    private static final Logger log = LoggerFactory.getLogger(DefaultCredentialStore.class);
    private final TokenManagementService tokenManager;
    private final File storeFile;
    private final Properties props = new Properties();

    public DefaultCredentialStore(String dataDirPath) {
        this.tokenManager = new TokenManagementService(dataDirPath);
        File dir = new File(dataDirPath, "credentials");
        if (!dir.exists()) {
            dir.mkdirs();
        }
        this.storeFile = new File(dir, "vault.properties");
        load();
    }

    public DefaultCredentialStore(TokenManagementService tokenManager, String dataDirPath) {
        this.tokenManager = tokenManager;
        File dir = new File(dataDirPath, "credentials");
        if (!dir.exists()) {
            dir.mkdirs();
        }
        this.storeFile = new File(dir, "vault.properties");
        load();
    }

    public TokenManagementService getTokenManager() {
        return tokenManager;
    }

    private synchronized void load() {
        if (storeFile.exists() && storeFile.isFile()) {
            try (FileInputStream fis = new FileInputStream(storeFile)) {
                props.load(fis);
            } catch (IOException e) {
                log.warn("Failed to read credential vault: {}", e.getMessage());
            }
        }
    }

    private synchronized void persist() {
        try (FileOutputStream fos = new FileOutputStream(storeFile)) {
            props.store(fos, "MailShield Secured Local Credential Vault");
        } catch (IOException e) {
            log.error("Failed to persist credential vault: {}", e.getMessage());
        }
    }

    @Override
    public synchronized void saveSecret(String key, String secret) {
        if (key == null || secret == null) return;
        tokenManager.saveEncryptedString(key, secret);
        props.setProperty(key, "AES256GCM:vault");
        persist();
    }

    @Override
    public synchronized Optional<String> getSecret(String key) {
        if (key == null) return Optional.empty();
        Optional<String> decrypted = tokenManager.loadDecryptedString(key);
        if (decrypted.isPresent()) {
            return decrypted;
        }
        // Fallback for legacy keys if any
        String val = props.getProperty(key);
        if (val != null && !val.isBlank() && !val.startsWith("AES256GCM:")) {
            return Optional.of(val);
        }
        return Optional.empty();
    }

    @Override
    public synchronized void removeSecret(String key) {
        if (key != null) {
            tokenManager.deleteToken(key);
            if (props.containsKey(key)) {
                props.remove(key);
                persist();
            }
        }
    }

    @Override
    public synchronized boolean hasSecret(String key) {
        if (key == null) return false;
        return tokenManager.hasToken(key) || props.containsKey(key);
    }
}


