package com.mailshield.detection;

import com.mailshield.model.EmailMessage;
import com.mailshield.model.Finding;

import java.util.List;

/**
 * Analyzes email body content for social engineering, urgency, extortion, and credential harvesting patterns.
 */
public interface ContentAnalyzer {
    List<Finding> analyzeContent(EmailMessage message);
}

