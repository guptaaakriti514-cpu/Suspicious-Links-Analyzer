package com.mailshield.model;

import java.time.Instant;
import java.util.*;

/**
 * Complete analysis record linking an EmailMessage to its RiskAssessment, Findings, and Intelligence Lookups.
 */
public final class AnalysisResult {
    private final String analysisId;
    private final String emailMessageId;
    private final RiskAssessment riskAssessment;
    private final List<Finding> findings;
    private final List<String> intelligenceReports;
    private final Instant analyzedAt;
    private final String ruleEngineVersion;

    public AnalysisResult(String analysisId, String emailMessageId, RiskAssessment riskAssessment,
                          List<Finding> findings, List<String> intelligenceReports,
                          Instant analyzedAt, String ruleEngineVersion) {
        this.analysisId = analysisId != null ? analysisId : UUID.randomUUID().toString();
        this.emailMessageId = emailMessageId != null ? emailMessageId : "";
        this.riskAssessment = riskAssessment != null ? riskAssessment : RiskAssessment.insufficientData("No assessment generated.");
        this.findings = findings != null ? Collections.unmodifiableList(new ArrayList<>(findings)) : Collections.emptyList();
        this.intelligenceReports = intelligenceReports != null ? Collections.unmodifiableList(new ArrayList<>(intelligenceReports)) : Collections.emptyList();
        this.analyzedAt = analyzedAt != null ? analyzedAt : Instant.now();
        this.ruleEngineVersion = ruleEngineVersion != null ? ruleEngineVersion : "1.0.0";
    }

    public String getAnalysisId() {
        return analysisId;
    }

    public String getEmailMessageId() {
        return emailMessageId;
    }

    public RiskAssessment getRiskAssessment() {
        return riskAssessment;
    }

    public List<Finding> getFindings() {
        return findings;
    }

    public List<String> getIntelligenceReports() {
        return intelligenceReports;
    }

    public Instant getAnalyzedAt() {
        return analyzedAt;
    }

    public String getRuleEngineVersion() {
        return ruleEngineVersion;
    }

    public int getCriticalFindingCount() {
        return (int) findings.stream().filter(f -> f.getSeverity() == Severity.CRITICAL).count();
    }

    public int getHighFindingCount() {
        return (int) findings.stream().filter(f -> f.getSeverity() == Severity.HIGH).count();
    }

    public int getMediumFindingCount() {
        return (int) findings.stream().filter(f -> f.getSeverity() == Severity.MEDIUM).count();
    }

    public int getLowFindingCount() {
        return (int) findings.stream().filter(f -> f.getSeverity() == Severity.LOW).count();
    }

    public int getInfoFindingCount() {
        return (int) findings.stream().filter(f -> f.getSeverity() == Severity.INFO).count();
    }
}

