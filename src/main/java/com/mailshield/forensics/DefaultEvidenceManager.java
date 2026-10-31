package com.mailshield.forensics;

import com.mailshield.model.EmailMessage;
import com.mailshield.model.EvidenceRecord;
import com.mailshield.storage.CaseRepository;
import com.mailshield.util.SecurityUtils;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Digital Forensics Evidence Custody Manager.
 * Computes deterministic SHA-256 cryptographic hashes over original ingested raw bytes
 * and tracks immutable chain-of-custody records.
 */
public class DefaultEvidenceManager implements EvidenceManager {

    private final CaseRepository caseRepository;

    public DefaultEvidenceManager(CaseRepository caseRepository) {
        this.caseRepository = caseRepository;
    }

    @Override
    public String computeSha256(byte[] bytes) {
        return SecurityUtils.sha256Hex(bytes);
    }

    @Override
    public String computeSha256(String text) {
        return SecurityUtils.sha256Hex(text != null ? text.getBytes(StandardCharsets.UTF_8) : new byte[0]);
    }

    @Override
    public EvidenceRecord recordEvidence(EmailMessage message, String caseId, String sourceDescription) {
        byte[] raw = message.getRawBytes();
        String rawHash = message.getRawSha256().isBlank() ? computeSha256(raw) : message.getRawSha256();
        String normalizedHash = computeSha256(message.getSubject() + "\n" + message.getBodyText());

        EvidenceRecord record = new EvidenceRecord(
                "EVD-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(),
                caseId != null ? caseId : "",
                rawHash,
                normalizedHash,
                "SHA-256",
                Instant.now(),
                "RFC 5322 Ingested Message",
                sourceDescription != null ? sourceDescription : message.getProviderSource().getTitle(),
                raw.length,
                "Original message bytes cryptographically hashed upon reception. Stored in tamper-evident audit repository."
        );

        if (caseRepository != null) {
            caseRepository.saveEvidence(record);
        }

        return record;
    }

    @Override
    public List<EvidenceRecord> getEvidenceForCase(String caseId) {
        if (caseRepository != null) {
            return caseRepository.findEvidenceByCaseId(caseId);
        }
        return List.of();
    }
}

