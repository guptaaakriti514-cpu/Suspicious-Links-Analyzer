package com.mailshield.scoring;

import com.mailshield.model.*;

import java.util.*;

/**
 * Explainable, deterministic risk scoring engine.
 * Employs category ceiling caps to prevent score inflation and correlated indicator duplication.
 * Evaluates rule weights, confidence levels, and categorical contributions.
 */
public class DefaultRiskScoringEngine implements RiskScoringEngine {

    public static final String ENGINE_VERSION = "2.1.0-explainable";

    // Maximum score contribution allowed per category to prevent correlated indicator bias
    private static final Map<FindingCategory, Integer> CATEGORY_CEILINGS = Map.of(
            FindingCategory.SUSPICIOUS_ATTACHMENT, 50,
            FindingCategory.SUSPICIOUS_URL, 45,
            FindingCategory.THREAT_INTELLIGENCE, 45,
            FindingCategory.SPOOFING_IMPERSONATION, 40,
            FindingCategory.AUTHENTICATION_FAILURE, 35,
            FindingCategory.SOCIAL_ENGINEERING, 30,
            FindingCategory.HEADER_ANOMALY, 25,
            FindingCategory.CONTENT_HEURISTIC, 20
    );

    // Baseline point weights by severity
    private static final Map<Severity, Integer> SEVERITY_BASE_POINTS = Map.of(
            Severity.CRITICAL, 35,
            Severity.HIGH, 20,
            Severity.MEDIUM, 10,
            Severity.LOW, 5,
            Severity.INFO, 0
    );

    @Override
    public RiskAssessment evaluateRisk(EmailMessage message, List<Finding> findings) {
        if (message == null) {
            return RiskAssessment.insufficientData("No message provided for evaluation.");
        }

        // Insufficient data check
        if (message.getHeaders().isEmpty() && message.getBodyText().isBlank() && message.getBodyHtml().isBlank()) {
            return RiskAssessment.insufficientData("Message contains neither headers nor body content.");
        }

        if (findings == null || findings.isEmpty()) {
            Map<FindingCategory, Integer> emptyScores = new EnumMap<>(FindingCategory.class);
            return new RiskAssessment(
                    RiskLevel.LOW,
                    0,
                    0.90,
                    "No anomalous indicators or security rule violations detected in message headers, body, or attachments.",
                    emptyScores,
                    ENGINE_VERSION,
                    false
            );
        }

        Map<FindingCategory, Integer> categoryRawScores = new EnumMap<>(FindingCategory.class);
        double totalWeightedConfidence = 0.0;
        int findingCountWithConfidence = 0;
        boolean hasCritical = false;

        // Group findings by category and calculate weighted contributions
        for (Finding f : findings) {
            FindingCategory cat = f.getCategory();
            int basePoints = SEVERITY_BASE_POINTS.getOrDefault(f.getSeverity(), 0);
            double conf = f.getConfidence();

            if (f.getSeverity() == Severity.CRITICAL) {
                hasCritical = true;
            }

            int weightedPoints = (int) Math.round(basePoints * conf);
            categoryRawScores.put(cat, categoryRawScores.getOrDefault(cat, 0) + weightedPoints);

            totalWeightedConfidence += conf;
            findingCountWithConfidence++;
        }

        // Apply category ceiling caps to avoid multi-count bias
        Map<FindingCategory, Integer> categoryFinalScores = new EnumMap<>(FindingCategory.class);
        int aggregateScore = 0;

        for (Map.Entry<FindingCategory, Integer> entry : categoryRawScores.entrySet()) {
            FindingCategory cat = entry.getKey();
            int raw = entry.getValue();
            int ceiling = CATEGORY_CEILINGS.getOrDefault(cat, 30);
            int capped = Math.min(raw, ceiling);
            categoryFinalScores.put(cat, capped);
            aggregateScore += capped;
        }

        // Any verified critical finding elevates baseline risk score to at least 80 (Critical threshold)
        if (hasCritical && aggregateScore < 80) {
            aggregateScore = Math.max(aggregateScore, 82);
        }

        int finalScore = Math.max(0, Math.min(100, aggregateScore));
        double aggregateConfidence = findingCountWithConfidence > 0 ? (totalWeightedConfidence / findingCountWithConfidence) : 0.8;

        // Determine Risk Level from threshold boundaries
        RiskLevel level;
        if (finalScore >= 80) {
            level = RiskLevel.CRITICAL;
        } else if (finalScore >= 55) {
            level = RiskLevel.HIGH;
        } else if (finalScore >= 25) {
            level = RiskLevel.MEDIUM;
        } else {
            level = RiskLevel.LOW;
        }

        // Generate explainable rationale string
        StringBuilder rationale = new StringBuilder();
        rationale.append("Risk evaluated as ").append(level.getLabel()).append(" (Score ").append(finalScore).append("/100). ");
        if (hasCritical) {
            rationale.append("Critical risk factors observed (e.g. executable attachment, credential phishing URL, or severe spoofing). ");
        }
        if (!categoryFinalScores.isEmpty()) {
            rationale.append("Primary contributing categories: ");
            List<String> topContributors = new ArrayList<>();
            categoryFinalScores.entrySet().stream()
                    .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                    .filter(e -> e.getValue() > 0)
                    .forEach(e -> topContributors.add(e.getKey().getLabel() + " (+" + e.getValue() + " pts)"));
            rationale.append(String.join(", ", topContributors)).append(".");
        }

        return new RiskAssessment(
                level,
                finalScore,
                aggregateConfidence,
                rationale.toString(),
                categoryFinalScores,
                ENGINE_VERSION,
                false
        );
    }

    @Override
    public String getVersion() {
        return ENGINE_VERSION;
    }
}

