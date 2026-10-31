package com.mailshield.model;

import java.time.Instant;
import java.util.*;

/**
 * An incident investigation case maintaining evidence, findings, and analyst notes.
 */
public final class InvestigationCase {
    private final String caseId;
    private final String title;
    private final CaseStatus status;
    private final CasePriority priority;
    private final Instant createdAt;
    private final Instant updatedAt;
    private final String analystNotes;
    private final String assignedAnalyst;
    private final List<String> associatedMessageIds;
    private final List<String> analysisResultIds;
    private final List<String> evidenceRecordIds;
    private final List<String> tags;

    public InvestigationCase(Builder builder) {
        this.caseId = builder.caseId != null ? builder.caseId : "CASE-" + System.currentTimeMillis();
        this.title = builder.title != null ? builder.title : "Untitled Investigation";
        this.status = builder.status != null ? builder.status : CaseStatus.OPEN;
        this.priority = builder.priority != null ? builder.priority : CasePriority.MEDIUM;
        this.createdAt = builder.createdAt != null ? builder.createdAt : Instant.now();
        this.updatedAt = builder.updatedAt != null ? builder.updatedAt : Instant.now();
        this.analystNotes = builder.analystNotes != null ? builder.analystNotes : "";
        this.assignedAnalyst = builder.assignedAnalyst != null ? builder.assignedAnalyst : "SOC Analyst";
        this.associatedMessageIds = Collections.unmodifiableList(new ArrayList<>(builder.associatedMessageIds));
        this.analysisResultIds = Collections.unmodifiableList(new ArrayList<>(builder.analysisResultIds));
        this.evidenceRecordIds = Collections.unmodifiableList(new ArrayList<>(builder.evidenceRecordIds));
        this.tags = Collections.unmodifiableList(new ArrayList<>(builder.tags));
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getCaseId() {
        return caseId;
    }

    public String getTitle() {
        return title;
    }

    public CaseStatus getStatus() {
        return status;
    }

    public CasePriority getPriority() {
        return priority;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public String getAnalystNotes() {
        return analystNotes;
    }

    public String getAssignedAnalyst() {
        return assignedAnalyst;
    }

    public List<String> getAssociatedMessageIds() {
        return associatedMessageIds;
    }

    public List<String> getAnalysisResultIds() {
        return analysisResultIds;
    }

    public List<String> getEvidenceRecordIds() {
        return evidenceRecordIds;
    }

    public List<String> getTags() {
        return tags;
    }

    public static class Builder {
        private String caseId;
        private String title = "New Email Investigation";
        private CaseStatus status = CaseStatus.OPEN;
        private CasePriority priority = CasePriority.MEDIUM;
        private Instant createdAt = Instant.now();
        private Instant updatedAt = Instant.now();
        private String analystNotes = "";
        private String assignedAnalyst = "Security Analyst";
        private List<String> associatedMessageIds = new ArrayList<>();
        private List<String> analysisResultIds = new ArrayList<>();
        private List<String> evidenceRecordIds = new ArrayList<>();
        private List<String> tags = new ArrayList<>();

        public Builder caseId(String id) { this.caseId = id; return this; }
        public Builder title(String title) { this.title = title; return this; }
        public Builder status(CaseStatus status) { this.status = status; return this; }
        public Builder priority(CasePriority priority) { this.priority = priority; return this; }
        public Builder createdAt(Instant at) { this.createdAt = at; return this; }
        public Builder updatedAt(Instant at) { this.updatedAt = at; return this; }
        public Builder analystNotes(String notes) { this.analystNotes = notes; return this; }
        public Builder assignedAnalyst(String analyst) { this.assignedAnalyst = analyst; return this; }
        public Builder associatedMessageIds(List<String> ids) { if (ids != null) this.associatedMessageIds = new ArrayList<>(ids); return this; }
        public Builder analysisResultIds(List<String> ids) { if (ids != null) this.analysisResultIds = new ArrayList<>(ids); return this; }
        public Builder evidenceRecordIds(List<String> ids) { if (ids != null) this.evidenceRecordIds = new ArrayList<>(ids); return this; }
        public Builder tags(List<String> tags) { if (tags != null) this.tags = new ArrayList<>(tags); return this; }

        public InvestigationCase build() {
            return new InvestigationCase(this);
        }
    }
}

