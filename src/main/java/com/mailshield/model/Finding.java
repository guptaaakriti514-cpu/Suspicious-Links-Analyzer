package com.mailshield.model;

import java.util.Objects;
import java.util.UUID;

/**
 * A concrete, explainable detection finding backed by evidence.
 */
public final class Finding {
    private final String id;
    private final String ruleId;
    private final String ruleVersion;
    private final FindingCategory category;
    private final Severity severity;
    private final double confidence; // 0.0 to 1.0 (documented indicator confidence, NOT phishing probability)
    private final String shortDescription;
    private final String explanation;
    private final String evidenceSnippet;
    private final String sourceLocation;
    private final FindingType findingType;
    private final String safeNextStep;

    public Finding(String id, String ruleId, String ruleVersion, FindingCategory category,
                   Severity severity, double confidence, String shortDescription, String explanation,
                   String evidenceSnippet, String sourceLocation, FindingType findingType,
                   String safeNextStep) {
        this.id = id != null ? id : UUID.randomUUID().toString();
        this.ruleId = ruleId != null ? ruleId : "GEN-001";
        this.ruleVersion = ruleVersion != null ? ruleVersion : "1.0.0";
        this.category = category != null ? category : FindingCategory.CONTENT_HEURISTIC;
        this.severity = severity != null ? severity : Severity.INFO;
        this.confidence = Math.max(0.0, Math.min(1.0, confidence));
        this.shortDescription = shortDescription != null ? shortDescription : "";
        this.explanation = explanation != null ? explanation : "";
        this.evidenceSnippet = evidenceSnippet != null ? evidenceSnippet : "";
        this.sourceLocation = sourceLocation != null ? sourceLocation : "Message Content";
        this.findingType = findingType != null ? findingType : FindingType.HEURISTIC;
        this.safeNextStep = safeNextStep != null ? safeNextStep : "Exercise caution and inspect headers.";
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getId() {
        return id;
    }

    public String getRuleId() {
        return ruleId;
    }

    public String getRuleVersion() {
        return ruleVersion;
    }

    public FindingCategory getCategory() {
        return category;
    }

    public Severity getSeverity() {
        return severity;
    }

    public double getConfidence() {
        return confidence;
    }

    public String getFormattedConfidence() {
        return String.format("%.0f%%", confidence * 100);
    }

    public String getShortDescription() {
        return shortDescription;
    }

    public String getExplanation() {
        return explanation;
    }

    public String getEvidenceSnippet() {
        return evidenceSnippet;
    }

    public String getSourceLocation() {
        return sourceLocation;
    }

    public FindingType getFindingType() {
        return findingType;
    }

    public String getSafeNextStep() {
        return safeNextStep;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Finding finding = (Finding) o;
        return Objects.equals(ruleId, finding.ruleId) &&
               Objects.equals(evidenceSnippet, finding.evidenceSnippet);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ruleId, evidenceSnippet);
    }

    @Override
    public String toString() {
        return String.format("[%s][%s] %s: %s", severity, ruleId, shortDescription, evidenceSnippet);
    }

    public static class Builder {
        private String id;
        private String ruleId = "RULE-001";
        private String ruleVersion = "1.0.0";
        private FindingCategory category = FindingCategory.CONTENT_HEURISTIC;
        private Severity severity = Severity.INFO;
        private double confidence = 0.8;
        private String shortDescription = "";
        private String explanation = "";
        private String evidenceSnippet = "";
        private String sourceLocation = "Message";
        private FindingType findingType = FindingType.HEURISTIC;
        private String safeNextStep = "Verify with sender through secondary out-of-band channel.";

        public Builder id(String id) { this.id = id; return this; }
        public Builder ruleId(String ruleId) { this.ruleId = ruleId; return this; }
        public Builder ruleVersion(String v) { this.ruleVersion = v; return this; }
        public Builder category(FindingCategory cat) { this.category = cat; return this; }
        public Builder severity(Severity sev) { this.severity = sev; return this; }
        public Builder confidence(double conf) { this.confidence = conf; return this; }
        public Builder shortDescription(String desc) { this.shortDescription = desc; return this; }
        public Builder explanation(String exp) { this.explanation = exp; return this; }
        public Builder evidenceSnippet(String snip) { this.evidenceSnippet = snip; return this; }
        public Builder sourceLocation(String loc) { this.sourceLocation = loc; return this; }
        public Builder findingType(FindingType type) { this.findingType = type; return this; }
        public Builder safeNextStep(String step) { this.safeNextStep = step; return this; }

        public Finding build() {
            return new Finding(id, ruleId, ruleVersion, category, severity, confidence,
                    shortDescription, explanation, evidenceSnippet, sourceLocation, findingType, safeNextStep);
        }
    }
}

