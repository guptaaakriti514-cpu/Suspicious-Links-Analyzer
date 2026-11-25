package com.mailshield.services;

import com.mailshield.detection.DetectionEngine;
import com.mailshield.intelligence.ThreatIntelligenceService;
import com.mailshield.model.AnalysisResult;
import com.mailshield.model.EmailMessage;
import com.mailshield.model.Finding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Enterprise Threat Detection Service.
 * Coordinates multi-vector analysis across headers, content, URLs, attachments,
 * and external threat intelligence indicators.
 */
public class ThreatDetectionService {

    private static final Logger log = LoggerFactory.getLogger(ThreatDetectionService.class);
    private final DetectionEngine detectionEngine;
    private final ThreatIntelligenceService threatIntelService;

    public ThreatDetectionService(DetectionEngine detectionEngine, ThreatIntelligenceService threatIntelService) {
        this.detectionEngine = detectionEngine;
        this.threatIntelService = threatIntelService;
    }

    public AnalysisResult analyzeEmail(EmailMessage message) {
        if (message == null) {
            log.warn("Null email passed to ThreatDetectionService");
            return detectionEngine.analyzeEmail(null);
        }
        log.debug("Analyzing email threat vectors for ID: {}", message.getId());
        return detectionEngine.analyzeEmail(message);
    }

    public List<Finding> checkUrl(String url) {
        if (threatIntelService != null && url != null && !url.isBlank()) {
            return threatIntelService.checkUrlReputation(url);
        }
        return List.of();
    }

    public List<Finding> checkDomain(String domain) {
        if (threatIntelService != null && domain != null && !domain.isBlank()) {
            return threatIntelService.checkDomainReputation(domain);
        }
        return List.of();
    }

    public ThreatIntelligenceService getThreatIntelService() {
        return threatIntelService;
    }
}
