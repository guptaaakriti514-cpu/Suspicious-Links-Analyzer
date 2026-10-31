package com.mailshield.detection;

import com.mailshield.model.EmailMessage;
import com.mailshield.model.Finding;

import java.util.List;

/**
 * Analyzes SPF, DKIM, and DMARC verdicts from Authentication-Results and Received-SPF headers.
 */
public interface AuthenticationResultAnalyzer {
    List<Finding> analyzeAuthentication(EmailMessage message);
}

