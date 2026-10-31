package com.mailshield.model;

import java.util.Collections;
import java.util.Map;

/**
 * Result of explainable risk evaluation across all detection analyzers.
 */
public final class RiskAssessment {
    private final RiskLevel riskLevel;
    private final int score; // 0 - 100
    private final double aggregateConfidence; // 0.0 - 1.0
    private final String explanation;
    private final Map<FindingCategory, Integer> categoryScores;
    private final String scoringEngineVersion;
    private final boolean isInsufficientData;

    public RiskAssessment(RiskLevel riskLevel, int score, double aggregateConfidence,
                          String explanation, Map<FindingCategory, Integer> categoryScores,
                          String scoringEngineVersion, boolean isInsufficientData) {
        this.riskLevel = riskLevel != null ? riskLevel : RiskLevel.INSUFFICIENT_DATA;
        this.score = Math.max(0, Math.min(100, score));
        this.aggregateConfidence = Math.max(0.0, Math.min(1.0, aggregateConfidence));
        this.explanation = explanation != null ? explanation : "";
        this.categoryScores = categoryScores != null ? Collections.unmodifiableMap(categoryScores) : Collections.emptyMap();
        this.scoringEngineVersion = scoringEngineVersion != null ? scoringEngineVersion : "1.0.0";
        this.isInsufficientData = isInsufficientData;
    }

    public static RiskAssessment insufficientData(String reason) {
        return new RiskAssessment(RiskLevel.INSUFFICIENT_DATA, 0, 0.0,
                reason != null ? reason : "Insufficient email headers or content to conduct complete analysis.",
                Collections.emptyMap(), "1.0.0", true);
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public int getScore() {
        return score;
    }

    public double getAggregateConfidence() {
        return aggregateConfidence;
    }

    public String getFormattedConfidence() {
        return String.format("%.0f%%", aggregateConfidence * 100);
    }

    public String getExplanation() {
        return explanation;
    }

    public Map<FindingCategory, Integer> getCategoryScores() {
        return categoryScores;
    }

    public String getScoringEngineVersion() {
        return scoringEngineVersion;
    }

    public boolean isInsufficientData() {
        return isInsufficientData;
    }

    @Override
    public String toString() {
        return String.format("%s (Score: %d/100, Conf: %s) - %s",
                riskLevel.getLabel(), score, getFormattedConfidence(), explanation);
    }
}

