package com.mailshield.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Immutable digital forensics evidence record capturing cryptographic hashes and custodial metadata.
 */
public final class EvidenceRecord {
    private final String evidenceId;
    private final String caseId;
    private final String rawMessageSha256;
    private final String normalizedContentSha256;
    private final String hashAlgorithm;
    private final Instant recordedAt;
    private final String evidenceType;
    private final String sourceDescription;
    private final long originalByteSize;
    private final String integrityNotes;

    public EvidenceRecord(String evidenceId, String caseId, String rawMessageSha256,
                          String normalizedContentSha256, String hashAlgorithm, Instant recordedAt,
                          String evidenceType, String sourceDescription, long originalByteSize,
                          String integrityNotes) {
        this.evidenceId = evidenceId != null ? evidenceId : UUID.randomUUID().toString();
        this.caseId = caseId != null ? caseId : "";
        this.rawMessageSha256 = rawMessageSha256 != null ? rawMessageSha256.toLowerCase() : "";
        this.normalizedContentSha256 = normalizedContentSha256 != null ? normalizedContentSha256.toLowerCase() : "";
        this.hashAlgorithm = hashAlgorithm != null ? hashAlgorithm : "SHA-256";
        this.recordedAt = recordedAt != null ? recordedAt : Instant.now();
        this.evidenceType = evidenceType != null ? evidenceType : "EMAIL_PAYLOAD";
        this.sourceDescription = sourceDescription != null ? sourceDescription : "Direct Ingestion";
        this.originalByteSize = Math.max(0, originalByteSize);
        this.integrityNotes = integrityNotes != null ? integrityNotes :
                "Forensic hash calculated immediately upon local ingestion. Stored in local tamper-evident SQLite repository.";
    }

    public String getEvidenceId() {
        return evidenceId;
    }

    public String getCaseId() {
        return caseId;
    }

    public String getRawMessageSha256() {
        return rawMessageSha256;
    }

    public String getNormalizedContentSha256() {
        return normalizedContentSha256;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public Instant getRecordedAt() {
        return recordedAt;
    }

    public String getEvidenceType() {
        return evidenceType;
    }

    public String getSourceDescription() {
        return sourceDescription;
    }

    public long getOriginalByteSize() {
        return originalByteSize;
    }

    public String getIntegrityNotes() {
        return integrityNotes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EvidenceRecord that = (EvidenceRecord) o;
        return Objects.equals(evidenceId, that.evidenceId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(evidenceId);
    }
}

