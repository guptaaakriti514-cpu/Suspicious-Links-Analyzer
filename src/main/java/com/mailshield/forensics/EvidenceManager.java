package com.mailshield.forensics;

import com.mailshield.model.EmailMessage;
import com.mailshield.model.EvidenceRecord;

import java.util.List;

/**
 * Service contract for forensic hash generation and custodial evidence record management.
 */
public interface EvidenceManager {

    /**
     * Compute SHA-256 hash string over raw input bytes.
     *
     * @param bytes byte array
     * @return 64-character lowercase hex string
     */
    String computeSha256(byte[] bytes);

    /**
     * Compute SHA-256 hash string over string content using UTF-8 encoding.
     *
     * @param text string content
     * @return 64-character lowercase hex string
     */
    String computeSha256(String text);

    /**
     * Create an immutable evidence record for an ingested email.
     *
     * @param message Ingested message
     * @param caseId Associated case ID
     * @param sourceDescription Origin metadata
     * @return EvidenceRecord
     */
    EvidenceRecord recordEvidence(EmailMessage message, String caseId, String sourceDescription);

    /**
     * Retrieve all evidence records for a case.
     */
    List<EvidenceRecord> getEvidenceForCase(String caseId);
}

