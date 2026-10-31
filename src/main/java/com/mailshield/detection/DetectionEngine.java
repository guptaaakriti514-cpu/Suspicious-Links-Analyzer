package com.mailshield.detection;

import com.mailshield.intelligence.ThreatIntelligenceService;
import com.mailshield.model.*;
import com.mailshield.scoring.RiskScoringEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.*;

/**
 * Master detection pipeline coordinator.
 * Executes header, content, URL, attachment, and threat intelligence analyzers,
 * consolidates findings without duplicates, and computes explainable risk scoring.
 */
public class DetectionEngine {

    private static final Logger log = LoggerFactory.getLogger(DetectionEngine.class);

    private final HeaderAnalyzer headerAnalyzer;
    private final ContentAnalyzer contentAnalyzer;
    private final UrlAnalyzer urlAnalyzer;
    private final AttachmentMetadataAnalyzer attachmentAnalyzer;
    private final ThreatIntelligenceService threatIntelService;
    private final RiskScoringEngine scoringEngine;

    public DetectionEngine(HeaderAnalyzer headerAnalyzer, ContentAnalyzer contentAnalyzer,
                           UrlAnalyzer urlAnalyzer, AttachmentMetadataAnalyzer attachmentAnalyzer,
                           ThreatIntelligenceService threatIntelService, RiskScoringEngine scoringEngine) {
        this.headerAnalyzer = headerAnalyzer != null ? headerAnalyzer : new SafeHeaderAnalyzer();
        this.contentAnalyzer = contentAnalyzer != null ? contentAnalyzer : new SafeContentAnalyzer();
        this.urlAnalyzer = urlAnalyzer != null ? urlAnalyzer : new SafeUrlAnalyzer();
        this.attachmentAnalyzer = attachmentAnalyzer != null ? attachmentAnalyzer : new SafeAttachmentAnalyzer();
        this.threatIntelService = threatIntelService;
        this.scoringEngine = scoringEngine;
    }

    public AnalysisResult analyzeEmail(EmailMessage message) {
        if (message == null) {
            return new AnalysisResult(UUID.randomUUID().toString(), "",
                    RiskAssessment.insufficientData("No message provided."),
                    Collections.emptyList(), Collections.emptyList(), Instant.now(), scoringEngine.getVersion());
        }

        List<Finding> consolidatedFindings = new ArrayList<>();
        List<String> intelReports = new ArrayList<>();

        // 1. Header Analysis
        try {
            consolidatedFindings.addAll(headerAnalyzer.analyzeHeaders(message));
        } catch (Exception e) {
            log.error("Header analysis error: {}", e.getMessage(), e);
        }

        // 2. Content & Social Engineering Analysis
        try {
            consolidatedFindings.addAll(contentAnalyzer.analyzeContent(message));
        } catch (Exception e) {
            log.error("Content analysis error: {}", e.getMessage(), e);
        }

        // 3. URL Analysis
        try {
            consolidatedFindings.addAll(urlAnalyzer.analyzeUrls(message));
        } catch (Exception e) {
            log.error("URL analysis error: {}", e.getMessage(), e);
        }

        // 4. Attachment Metadata Analysis
        try {
            consolidatedFindings.addAll(attachmentAnalyzer.analyzeAttachments(message));
        } catch (Exception e) {
            log.error("Attachment analysis error: {}", e.getMessage(), e);
        }

        // 5. Threat Intelligence Reputation Feeds
        if (threatIntelService != null) {
            try {
                // Check sender domain
                String senderDomain = message.getSenderDomain();
                if (!senderDomain.isBlank()) {
                    List<Finding> domainFindings = threatIntelService.checkDomainReputation(senderDomain);
                    consolidatedFindings.addAll(domainFindings);
                    if (!domainFindings.isEmpty()) {
                        intelReports.add("Sender domain flagged: " + senderDomain + " (" + threatIntelService.getProviderName() + ")");
                    }
                }

                // Check extracted URLs
                for (ExtractedUrl u : message.getExtractedUrls()) {
                    List<Finding> urlFindings = threatIntelService.checkUrlReputation(u.getNormalizedUrl());
                    consolidatedFindings.addAll(urlFindings);
                    if (!urlFindings.isEmpty()) {
                        intelReports.add("URL flagged: " + u.getOriginalUrl() + " (" + threatIntelService.getProviderName() + ")");
                    }
                }

                // Check attachment hashes
                for (EmailAttachmentMetadata att : message.getAttachments()) {
                    if (!att.getSha256Hash().isBlank()) {
                        List<Finding> hashFindings = threatIntelService.checkHashReputation(att.getSha256Hash(), att.getFilename());
                        consolidatedFindings.addAll(hashFindings);
                        if (!hashFindings.isEmpty()) {
                            intelReports.add("Attachment hash flagged: " + att.getFilename() + " (" + threatIntelService.getProviderName() + ")");
                        }
                    }
                }
            } catch (Exception e) {
                log.error("Threat intelligence query error: {}", e.getMessage(), e);
            }
        }

        // Deduplicate findings by ruleId and evidence
        List<Finding> uniqueFindings = deduplicateFindings(consolidatedFindings);

        // 6. Compute Explainable Risk Score
        RiskAssessment riskAssessment = scoringEngine.evaluateRisk(message, uniqueFindings);

        return new AnalysisResult(
                UUID.randomUUID().toString(),
                message.getId(),
                riskAssessment,
                uniqueFindings,
                intelReports,
                Instant.now(),
                scoringEngine.getVersion()
        );
    }

    private List<Finding> deduplicateFindings(List<Finding> findings) {
        Set<String> seen = new HashSet<>();
        List<Finding> unique = new ArrayList<>();
        for (Finding f : findings) {
            String key = f.getRuleId() + ":" + f.getEvidenceSnippet().toLowerCase().trim();
            if (seen.add(key)) {
                unique.add(f);
            }
        }
        return unique;
    }

    public HeaderAnalyzer getHeaderAnalyzer() { return headerAnalyzer; }
    public ContentAnalyzer getContentAnalyzer() { return contentAnalyzer; }
    public UrlAnalyzer getUrlAnalyzer() { return urlAnalyzer; }
    public AttachmentMetadataAnalyzer getAttachmentAnalyzer() { return attachmentAnalyzer; }
    public ThreatIntelligenceService getThreatIntelService() { return threatIntelService; }
    public RiskScoringEngine getScoringEngine() { return scoringEngine; }
}

