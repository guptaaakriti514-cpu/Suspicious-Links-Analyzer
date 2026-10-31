package com.mailshield.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Represents a URL safely extracted from an email message (plain text or HTML).
 */
public final class ExtractedUrl {
    private final String originalUrl;
    private final String normalizedUrl;
    private final String domain;
    private final String path;
    private final String scheme;
    private final String anchorText;
    private final boolean isShortened;
    private final boolean isIpHost;
    private final boolean hasHomograph;
    private final boolean isPunycode;
    private final boolean hasUserInfo;
    private final boolean isMismatchWithAnchor;
    private final List<String> suspiciousReasons;

    public ExtractedUrl(String originalUrl, String normalizedUrl, String domain, String path, String scheme,
                        String anchorText, boolean isShortened, boolean isIpHost, boolean hasHomograph,
                        boolean isPunycode, boolean hasUserInfo, boolean isMismatchWithAnchor,
                        List<String> suspiciousReasons) {
        this.originalUrl = originalUrl != null ? originalUrl.trim() : "";
        this.normalizedUrl = normalizedUrl != null ? normalizedUrl.trim() : "";
        this.domain = domain != null ? domain.trim().toLowerCase() : "";
        this.path = path != null ? path.trim() : "";
        this.scheme = scheme != null ? scheme.trim().toLowerCase() : "http";
        this.anchorText = anchorText != null ? anchorText.trim() : "";
        this.isShortened = isShortened;
        this.isIpHost = isIpHost;
        this.hasHomograph = hasHomograph;
        this.isPunycode = isPunycode;
        this.hasUserInfo = hasUserInfo;
        this.isMismatchWithAnchor = isMismatchWithAnchor;
        this.suspiciousReasons = suspiciousReasons != null ? Collections.unmodifiableList(new ArrayList<>(suspiciousReasons)) : Collections.emptyList();
    }

    public String getOriginalUrl() {
        return originalUrl;
    }

    public String getNormalizedUrl() {
        return normalizedUrl;
    }

    public String getDomain() {
        return domain;
    }

    public String getPath() {
        return path;
    }

    public String getScheme() {
        return scheme;
    }

    public String getAnchorText() {
        return anchorText;
    }

    public boolean isShortened() {
        return isShortened;
    }

    public boolean isIpHost() {
        return isIpHost;
    }

    public boolean hasHomograph() {
        return hasHomograph;
    }

    public boolean isPunycode() {
        return isPunycode;
    }

    public boolean hasUserInfo() {
        return hasUserInfo;
    }

    public boolean isMismatchWithAnchor() {
        return isMismatchWithAnchor;
    }

    public List<String> getSuspiciousReasons() {
        return suspiciousReasons;
    }

    public boolean isSuspicious() {
        return !suspiciousReasons.isEmpty() || isShortened || isIpHost || hasHomograph || hasUserInfo || isMismatchWithAnchor;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ExtractedUrl that = (ExtractedUrl) o;
        return Objects.equals(normalizedUrl, that.normalizedUrl) && Objects.equals(anchorText, that.anchorText);
    }

    @Override
    public int hashCode() {
        return Objects.hash(normalizedUrl, anchorText);
    }

    @Override
    public String toString() {
        return originalUrl + (anchorText.isEmpty() ? "" : " [text: " + anchorText + "]");
    }
}

