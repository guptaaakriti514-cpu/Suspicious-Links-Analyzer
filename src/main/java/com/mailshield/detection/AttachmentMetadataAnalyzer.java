package com.mailshield.detection;

import com.mailshield.model.EmailMessage;
import com.mailshield.model.Finding;

import java.util.List;

/**
 * Analyzes attachment metadata (extensions, double extensions, executable types, mime mismatches).
 * Never executes or unpacks binaries.
 */
public interface AttachmentMetadataAnalyzer {
    List<Finding> analyzeAttachments(EmailMessage message);
}

