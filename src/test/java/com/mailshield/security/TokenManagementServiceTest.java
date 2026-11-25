package com.mailshield.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenManagementServiceTest {

    @TempDir
    File tempDir;

    private TokenManagementService tokenManager;

    @BeforeEach
    void setUp() {
        tokenManager = new TokenManagementService(tempDir.getAbsolutePath());
    }

    @Test
    void shouldEncryptAndDecryptSuccessfully() {
        String secret = "oauth-refresh-token-secret-1234567890-test";
        byte[] plaintext = secret.getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = tokenManager.encrypt(plaintext);
        assertThat(encrypted).isNotEqualTo(plaintext);
        assertThat(encrypted.length).isGreaterThan(plaintext.length);

        byte[] decrypted = tokenManager.decrypt(encrypted);
        assertThat(new String(decrypted, StandardCharsets.UTF_8)).isEqualTo(secret);
    }

    @Test
    void shouldDetectTamperingInCiphertext() {
        byte[] plaintext = "authentic-user-token".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = tokenManager.encrypt(plaintext);

        // Tamper with one byte in the ciphertext payload
        encrypted[encrypted.length - 1] ^= 0x55;

        assertThatThrownBy(() -> tokenManager.decrypt(encrypted))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("tampering detected");
    }

    @Test
    void shouldPersistAndLoadEncryptedStrings() {
        String tokenKey = "google_refresh_token";
        String tokenValue = "1//04testGoogleRefreshTokenLongAlphaNumericString";

        tokenManager.saveEncryptedString(tokenKey, tokenValue);
        assertThat(tokenManager.hasToken(tokenKey)).isTrue();

        Optional<String> loaded = tokenManager.loadDecryptedString(tokenKey);
        assertThat(loaded).isPresent();
        assertThat(loaded.get()).isEqualTo(tokenValue);

        tokenManager.deleteToken(tokenKey);
        assertThat(tokenManager.hasToken(tokenKey)).isFalse();
        assertThat(tokenManager.loadDecryptedString(tokenKey)).isEmpty();
    }
}
