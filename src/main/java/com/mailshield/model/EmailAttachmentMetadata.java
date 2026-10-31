package com.mailshield.model;

import java.util.Objects;

/**
 * Metadata representing an email attachment. Never opens or executes attachment content.
 */
public final class EmailAttachmentMetadata {
    private final String filename;
    private final String contentType;
    private final long sizeBytes;
    private final String sha256Hash;
    private final boolean isSuspicious;
    private final String suspiciousReason;

    public EmailAttachmentMetadata(String filename, String contentType, long sizeBytes, String sha256Hash,
                                   boolean isSuspicious, String suspiciousReason) {
        this.filename = filename != null ? filename.trim() : "unnamed_attachment";
        this.contentType = contentType != null ? contentType.trim().toLowerCase() : "application/octet-stream";
        this.sizeBytes = Math.max(0, sizeBytes);
        this.sha256Hash = sha256Hash != null ? sha256Hash.toLowerCase() : "";
        this.isSuspicious = isSuspicious;
        this.suspiciousReason = suspiciousReason != null ? suspiciousReason : "";
    }

    public String getFilename() {
        return filename;
    }

    public String getContentType() {
        return contentType;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public String getSha256Hash() {
        return sha256Hash;
    }

    public boolean isSuspicious() {
        return isSuspicious;
    }

    public String getSuspiciousReason() {
        return suspiciousReason;
    }

    public String getFormattedSize() {
        if (sizeBytes < 1024) return sizeBytes + " B";
        if (sizeBytes < 1024 * 1024) return String.format("%.1f KB", sizeBytes / 1024.0);
        return String.format("%.2f MB", sizeBytes / (1024.0 * 1024.0));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EmailAttachmentMetadata that = (EmailAttachmentMetadata) o;
        return sizeBytes == that.sizeBytes &&
                Objects.equals(filename, that.filename) &&
                Objects.equals(contentType, that.contentType) &&
                Objects.equals(sha256Hash, that.sha256Hash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(filename, contentType, sizeBytes, sha256Hash);
    }

    @Override
    public String toString() {
        return filename + " (" + getFormattedSize() + ", " + contentType + ")";
    }
}

