package com.mailshield.scoring;

import com.mailshield.model.EmailMessage;
import com.mailshield.model.Finding;
import com.mailshield.model.RiskAssessment;

import java.util.List;

/**
 * Service contract for deterministic, explainable risk scoring.
 */
public interface RiskScoringEngine {

    /**
     * Compute risk score, level, and category breakdown based on findings and message metadata.
     *
     * @param message Analyzed email message
     * @param findings Consolidated findings from all analyzers
     * @return Explainable RiskAssessment
     */
    RiskAssessment evaluateRisk(EmailMessage message, List<Finding> findings);

    /**
     * Engine version string for reproducibility and audit trail.
     */
    String getVersion();
}

