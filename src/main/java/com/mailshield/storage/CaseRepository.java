package com.mailshield.storage;

import com.mailshield.model.AnalysisResult;
import com.mailshield.model.EmailMessage;
import com.mailshield.model.EvidenceRecord;
import com.mailshield.model.InvestigationCase;

import java.util.List;
import java.util.Optional;

/**
 * Service contract for persistent SQLite storage of cases, analyses, evidence, and checkpoints.
 */
public interface CaseRepository {

    void saveEmailMessage(EmailMessage message);
    Optional<EmailMessage> findEmailMessageById(String id);
    Optional<EmailMessage> findEmailMessageByProviderId(String providerMessageId);
    boolean hasEmailBeenProcessed(String providerMessageId);
    List<EmailMessage> findAllEmails(int limit, int offset);
    int getTotalEmailCount();

    void saveAnalysisResult(AnalysisResult result);
    Optional<AnalysisResult> findAnalysisResultByEmailId(String emailId);
    List<AnalysisResult> findRecentAnalyses(int limit);

    void saveCase(InvestigationCase investigationCase);
    Optional<InvestigationCase> findCaseById(String caseId);
    List<InvestigationCase> findAllCases(int limit, int offset);
    int getTotalCaseCount();
    void updateCaseNotes(String caseId, String notes, String status);

    void saveEvidence(EvidenceRecord record);
    List<EvidenceRecord> findEvidenceByCaseId(String caseId);

    // Monitoring Checkpoints
    void saveCheckpoint(String providerKey, String lastCheckpoint);
    Optional<String> getCheckpoint(String providerKey);

    // System stats
    int getHighRiskEmailCount();
    int getCriticalEmailCount();
    int getOpenCaseCount();

    void close();
}

