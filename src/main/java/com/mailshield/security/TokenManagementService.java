package com.mailshield.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

/**
 * Enterprise-grade Token & Credential Management Service.
 * Implements AES-256-GCM authenticated encryption at rest with random 96-bit IVs
 * and 128-bit authentication tags to prevent token tampering or exposure.
 * Automatically secures refresh tokens, MSAL session caches, and API secrets.
 */
public class TokenManagementService {

    private static final Logger log = LoggerFactory.getLogger(TokenManagementService.class);

    private static final String ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128; // bits
    private static final int GCM_IV_LENGTH = 12;   // bytes (96 bits recommended for GCM)
    private static final int AES_KEY_SIZE = 256;   // bits

    private final SecretKey masterKey;
    private final File tokenStorageDir;
    private final SecureRandom secureRandom = new SecureRandom();

    public TokenManagementService(String dataDirPath) {
        this.tokenStorageDir = new File(dataDirPath, "vault");
        if (!tokenStorageDir.exists()) {
            tokenStorageDir.mkdirs();
        }
        this.masterKey = initializeMasterKey(dataDirPath);
    }

    /**
     * Initializes or loads the 256-bit AES master key.
     * Prefers MAILSHIELD_MASTER_KEY environment variable if defined,
     * otherwise securely loads/creates master.key in data directory.
     */
    private SecretKey initializeMasterKey(String dataDirPath) {
        String envKey = System.getenv("MAILSHIELD_MASTER_KEY");
        if (envKey != null && !envKey.isBlank()) {
            try {
                byte[] decoded = Base64.getDecoder().decode(envKey.trim());
                if (decoded.length == 32) {
                    log.info("Loaded AES-256 master key from MAILSHIELD_MASTER_KEY environment variable.");
                    return new SecretKeySpec(decoded, ALGORITHM);
                }
            } catch (Exception e) {
                log.warn("Failed to decode MAILSHIELD_MASTER_KEY from environment, falling back to local vault key.");
            }
        }

        File keyDir = new File(dataDirPath, "credentials");
        if (!keyDir.exists()) {
            keyDir.mkdirs();
        }
        File keyFile = new File(keyDir, "master.key");

        if (keyFile.exists() && keyFile.length() == 32) {
            try (FileInputStream fis = new FileInputStream(keyFile)) {
                byte[] keyBytes = fis.readAllBytes();
                return new SecretKeySpec(keyBytes, ALGORITHM);
            } catch (IOException e) {
                log.error("Failed to read existing master key: {}", e.getMessage());
            }
        }

        // Generate new 256-bit AES key
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(AES_KEY_SIZE, secureRandom);
            SecretKey newKey = keyGen.generateKey();
            try (FileOutputStream fos = new FileOutputStream(keyFile)) {
                fos.write(newKey.getEncoded());
            }
            log.info("Generated new cryptographically secure AES-256 master key at {}", keyFile.getPath());
            return newKey;
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new IllegalStateException("Failed to initialize AES-256 master key", e);
        }
    }

    /**
     * Encrypts plaintext bytes using AES-256-GCM with a fresh random 96-bit IV.
     * Output format: [12-byte IV][Ciphertext + 16-byte GCM Tag]
     */
    public byte[] encrypt(byte[] plaintext) {
        if (plaintext == null || plaintext.length == 0) {
            return new byte[0];
        }
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, spec);

            byte[] cipherText = cipher.doFinal(plaintext);

            // Combine IV + cipherText
            byte[] output = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, output, 0, iv.length);
            System.arraycopy(cipherText, 0, output, iv.length, cipherText.length);
            return output;
        } catch (Exception e) {
            throw new SecurityException("AES-GCM encryption failed", e);
        }
    }

    /**
     * Decrypts ciphertext bytes using AES-256-GCM.
     * Verifies GCM authentication tag to detect any tampering.
     */
    public byte[] decrypt(byte[] encryptedWithIv) {
        if (encryptedWithIv == null || encryptedWithIv.length <= GCM_IV_LENGTH) {
            return new byte[0];
        }
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(encryptedWithIv, 0, iv, 0, GCM_IV_LENGTH);

            int cipherLength = encryptedWithIv.length - GCM_IV_LENGTH;
            byte[] cipherText = new byte[cipherLength];
            System.arraycopy(encryptedWithIv, GCM_IV_LENGTH, cipherText, 0, cipherLength);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, masterKey, spec);

            return cipher.doFinal(cipherText);
        } catch (Exception e) {
            throw new SecurityException("AES-GCM decryption failed or authentication tag mismatch (tampering detected)", e);
        }
    }

    /**
     * Encrypts and persists a string secret under the specified key name.
     */
    public synchronized void saveEncryptedString(String key, String secret) {
        if (key == null || secret == null) return;
        byte[] encrypted = encrypt(secret.getBytes(StandardCharsets.UTF_8));
        saveEncryptedBytes(key, encrypted);
    }

    /**
     * Loads and decrypts a string secret for the given key.
     */
    public synchronized Optional<String> loadDecryptedString(String key) {
        return loadEncryptedBytes(key).map(bytes -> new String(bytes, StandardCharsets.UTF_8));
    }

    /**
     * Saves raw encrypted bytes directly to the vault.
     */
    public synchronized void saveEncryptedBytes(String key, byte[] data) {
        if (key == null || data == null) return;
        File targetFile = getVaultFile(key);
        try {
            Files.write(targetFile.toPath(), data);
        } catch (IOException e) {
            log.error("Failed to write encrypted vault record for {}: {}", key, e.getMessage());
        }
    }

    /**
     * Loads and decrypts raw bytes from the vault.
     */
    public synchronized Optional<byte[]> loadEncryptedBytes(String key) {
        if (key == null) return Optional.empty();
        File targetFile = getVaultFile(key);
        if (!targetFile.exists() || !targetFile.isFile()) {
            return Optional.empty();
        }
        try {
            byte[] encrypted = Files.readAllBytes(targetFile.toPath());
            return Optional.of(decrypt(encrypted));
        } catch (Exception e) {
            log.warn("Failed to read or decrypt vault record for {}: {}", key, e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Securely deletes the token record associated with the key.
     */
    public synchronized void deleteToken(String key) {
        if (key == null) return;
        File targetFile = getVaultFile(key);
        if (targetFile.exists()) {
            try {
                // Overwrite with zeros before deletion (secure wipe)
                byte[] zeros = new byte[(int) targetFile.length()];
                Files.write(targetFile.toPath(), zeros);
                targetFile.delete();
                log.info("Securely wiped and deleted credential record: {}", key);
            } catch (Exception e) {
                targetFile.delete();
            }
        }
    }

    public synchronized boolean hasToken(String key) {
        if (key == null) return false;
        File f = getVaultFile(key);
        return f.exists() && f.length() > GCM_IV_LENGTH;
    }

    private File getVaultFile(String key) {
        // Sanitize key name to avoid path traversal
        String sanitized = key.replaceAll("[^a-zA-Z0-9._-]", "_");
        return new File(tokenStorageDir, sanitized + ".enc");
    }
}
