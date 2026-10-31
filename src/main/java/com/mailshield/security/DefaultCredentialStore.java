package com.mailshield.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Optional;
import java.util.Properties;

/**
 * Local credential store for OAuth tokens and API secrets.
 * Obfuscates stored tokens to prevent casual plaintext exposure in logs or filesystem.
 * Never logs secrets or tokens.
 */
public class DefaultCredentialStore implements CredentialStore {

    private static final Logger log = LoggerFactory.getLogger(DefaultCredentialStore.class);
    private final File storeFile;
    private final Properties props = new Properties();
    private static final byte[] XOR_SALT = new byte[]{ 0x4D, 0x61, 0x69, 0x6C, 0x53, 0x68, 0x69, 0x65, 0x6C, 0x64, 0x32, 0x31 };

    public DefaultCredentialStore(String dataDirPath) {
        File dir = new File(dataDirPath, "credentials");
        if (!dir.exists()) {
            dir.mkdirs();
        }
        this.storeFile = new File(dir, "vault.properties");
        load();
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
        String obfuscated = obfuscate(secret);
        props.setProperty(key, obfuscated);
        persist();
    }

    @Override
    public synchronized Optional<String> getSecret(String key) {
        if (key == null) return Optional.empty();
        String val = props.getProperty(key);
        if (val == null || val.isBlank()) return Optional.empty();
        return Optional.ofNullable(deobfuscate(val));
    }

    @Override
    public synchronized void removeSecret(String key) {
        if (key != null && props.containsKey(key)) {
            props.remove(key);
            persist();
        }
    }

    @Override
    public synchronized boolean hasSecret(String key) {
        return key != null && props.containsKey(key);
    }

    private String obfuscate(String input) {
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        byte[] result = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            result[i] = (byte) (bytes[i] ^ XOR_SALT[i % XOR_SALT.length]);
        }
        return Base64.getEncoder().encodeToString(result);
    }

    private String deobfuscate(String base64) {
        try {
            byte[] bytes = Base64.getDecoder().decode(base64);
            byte[] result = new byte[bytes.length];
            for (int i = 0; i < bytes.length; i++) {
                result[i] = (byte) (bytes[i] ^ XOR_SALT[i % XOR_SALT.length]);
            }
            return new String(result, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }
}

