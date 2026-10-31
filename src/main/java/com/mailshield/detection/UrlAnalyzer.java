package com.mailshield.detection;

import com.mailshield.model.EmailMessage;
import com.mailshield.model.ExtractedUrl;
import com.mailshield.model.Finding;

import java.util.List;

/**
 * Extracts and safely inspects URLs from email body and headers.
 */
public interface UrlAnalyzer {
    List<ExtractedUrl> extractUrls(String bodyText, String bodyHtml);
    List<Finding> analyzeUrls(EmailMessage message);
}

