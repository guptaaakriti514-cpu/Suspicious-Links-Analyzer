package com.mailshield.detection;

import com.mailshield.model.EmailMessage;
import com.mailshield.model.Finding;

import java.util.List;

/**
 * Analyzes RFC 5322 email headers for anomalies, sender spoofing, and hop inconsistencies.
 */
public interface HeaderAnalyzer {
    List<Finding> analyzeHeaders(EmailMessage message);
}

