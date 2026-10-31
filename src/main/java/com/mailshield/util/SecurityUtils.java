package com.mailshield.util;

import java.net.IDN;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/**
 * Common security, cryptographic, and sanitization utilities.
 */
public final class SecurityUtils {

    private SecurityUtils() {}

    /**
     * Compute SHA-256 hash over arbitrary byte array.
     */
    public static String sha256Hex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // Empty hash
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(bytes);
            StringBuilder hexString = new StringBuilder(2 * encodedhash.length);
            for (byte b : encodedhash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available in JVM", e);
        }
    }

    /**
     * Compute SHA-256 hash over string content in UTF-8.
     */
    public static String sha256Hex(String text) {
        if (text == null) return sha256Hex(new byte[0]);
        return sha256Hex(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * HTML entity escaping for untrusted user/email content in reports and UI.
     * Prevents XSS and HTML injection.
     */
    public static String escapeHtml(String input) {
        if (input == null) return "";
        StringBuilder out = new StringBuilder(Math.max(16, input.length()));
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '&' -> out.append("&amp;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#x27;");
                case '/' -> out.append("&#x2F;");
                default -> out.append(c);
            }
        }
        return out.toString();
    }

    /**
     * Safely normalize a domain name, handling internationalized domain names (IDN / Punycode).
     */
    public static String normalizeDomain(String rawDomain) {
        if (rawDomain == null) return "";
        String trimmed = rawDomain.trim().toLowerCase(Locale.ROOT);
        // Remove trailing dot if present
        if (trimmed.endsWith(".")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        try {
            // Convert to ASCII Punycode representation
            return IDN.toASCII(trimmed);
        } catch (Exception e) {
            return trimmed;
        }
    }

    /**
     * Extract root domain (e.g., "paypal.com" from "security.update.paypal.com").
     */
    public static String extractRegistrableDomain(String host) {
        if (host == null || host.isEmpty()) return "";
        String normalized = normalizeDomain(host);
        String[] parts = normalized.split("\\.");
        if (parts.length <= 2) return normalized;
        // Common two-level TLDs check (e.g. .co.uk, .gov.in, .com.au)
        String tldCandidate = parts[parts.length - 2] + "." + parts[parts.length - 1];
        if (tldCandidate.equals("co.uk") || tldCandidate.equals("gov.in") ||
            tldCandidate.equals("com.au") || tldCandidate.equals("org.uk") ||
            tldCandidate.equals("ac.in") || tldCandidate.equals("edu.in")) {
            if (parts.length >= 3) {
                return parts[parts.length - 3] + "." + tldCandidate;
            }
        }
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }
}

