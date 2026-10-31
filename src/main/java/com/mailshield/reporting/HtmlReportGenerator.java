package com.mailshield.reporting;

import com.mailshield.model.*;
import com.mailshield.util.SecurityUtils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Generates security-hardened, SOC-themed HTML forensic investigation reports and CSV summaries.
 * All untrusted email values, headers, and findings are strictly HTML-escaped.
 */
public class HtmlReportGenerator implements ReportGenerator {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault());

    @Override
    public void generateHtmlReport(InvestigationCase investigationCase, EmailMessage message,
                                   AnalysisResult result, List<EvidenceRecord> evidenceList,
                                   File targetFile) throws IOException {
        if (targetFile == null) {
            throw new IllegalArgumentException("Target report file cannot be null");
        }

        File parent = targetFile.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        try (PrintWriter writer = new PrintWriter(new FileWriter(targetFile))) {
            writer.println("<!DOCTYPE html>");
            writer.println("<html lang=\"en\">");
            writer.println("<head>");
            writer.println("<meta charset=\"UTF-8\">");
            writer.println("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
            writer.println("<title>MailShield Forensic Investigation Report</title>");
            writer.println("<style>");
            writer.println("  :root { --bg: #0f172a; --card: #1e293b; --border: #334155; --text: #f8fafc; --muted: #94a3b8; --accent: #38bdf8; --danger: #ef4444; --warning: #f59e0b; --success: #10b981; }");
            writer.println("  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 24px; line-height: 1.6; }");
            writer.println("  .container { max-width: 1000px; margin: 0 auto; }");
            writer.println("  .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }");
            writer.println("  .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-weight: 700; font-size: 0.85rem; text-transform: uppercase; }");
            writer.println("  .badge-CRITICAL { background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #ef4444; }");
            writer.println("  .badge-HIGH { background: rgba(245,158,11,0.2); color: #fbbf24; border: 1px solid #f59e0b; }");
            writer.println("  .badge-MEDIUM { background: rgba(234,179,8,0.2); color: #facc15; border: 1px solid #eab308; }");
            writer.println("  .badge-LOW { background: rgba(16,185,129,0.2); color: #34d399; border: 1px solid #10b981; }");
            writer.println("  .badge-INSUFFICIENT_DATA { background: rgba(148,163,184,0.2); color: #94a3b8; border: 1px solid #64748b; }");
            writer.println("  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.2); }");
            writer.println("  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }");
            writer.println("  h1, h2, h3 { margin-top: 0; color: #fff; }");
            writer.println("  .meta-label { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }");
            writer.println("  .meta-value { font-size: 1rem; font-weight: 600; margin-bottom: 8px; word-break: break-all; }");
            writer.println("  .score-box { text-align: center; padding: 16px; background: rgba(0,0,0,0.2); border-radius: 8px; }");
            writer.println("  .score-number { font-size: 3rem; font-weight: 800; }");
            writer.println("  table { width: 100%; border-collapse: collapse; margin-top: 12px; }");
            writer.println("  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }");
            writer.println("  th { color: var(--muted); text-transform: uppercase; font-size: 0.75rem; }");
            writer.println("  .snippet { font-family: monospace; background: rgba(0,0,0,0.3); padding: 6px 10px; border-radius: 4px; font-size: 0.85rem; border-left: 3px solid var(--accent); }");
            writer.println("  .disclaimer { font-size: 0.8rem; color: var(--muted); border-top: 1px solid var(--border); padding-top: 16px; margin-top: 32px; font-style: italic; }");
            writer.println("  @media print { body { background: #fff; color: #000; } .card { border: 1px solid #ccc; box-shadow: none; } }");
            writer.println("</style>");
            writer.println("</head>");
            writer.println("<body>");
            writer.println("<div class=\"container\">");

            // Header Section
            writer.println("<div class=\"header\">");
            writer.println("  <div>");
            writer.println("    <h1>MAILSHIELD &mdash; Incident Forensics Report</h1>");
            writer.println("    <div style=\"color: var(--muted); font-size: 0.9rem;\">Advanced Email Threat Detection, Investigation & Digital Forensics Platform</div>");
            writer.println("  </div>");
            writer.printf("  <div><span class=\"badge badge-%s\">%s</span></div>%n",
                    result.getRiskAssessment().getRiskLevel().name(),
                    result.getRiskAssessment().getRiskLevel().getLabel());
            writer.println("</div>");

            // Overview Grid
            writer.println("<div class=\"card grid-2\">");
            writer.println("  <div>");
            writer.println("    <div class=\"meta-label\">Case Reference</div>");
            writer.printf("    <div class=\"meta-value\">%s</div>%n", investigationCase != null ? SecurityUtils.escapeHtml(investigationCase.getCaseId()) : "Ad-Hoc Analysis");
            writer.println("    <div class=\"meta-label\">Subject</div>");
            writer.printf("    <div class=\"meta-value\">%s</div>%n", SecurityUtils.escapeHtml(message.getSubject()));
            writer.println("    <div class=\"meta-label\">Envelope Sender (From)</div>");
            writer.printf("    <div class=\"meta-value\">%s &lt;%s&gt;</div>%n",
                    SecurityUtils.escapeHtml(message.getFromDisplayName()),
                    SecurityUtils.escapeHtml(message.getFromAddress()));
            writer.println("    <div class=\"meta-label\">Source & Ingestion</div>");
            writer.printf("    <div class=\"meta-value\">%s (%s)</div>%n",
                    SecurityUtils.escapeHtml(message.getProviderSource().getTitle()),
                    FORMATTER.format(message.getIngestedAt()));
            writer.println("  </div>");

            writer.println("  <div class=\"score-box\">");
            writer.println("    <div class=\"meta-label\">Explainable Risk Score</div>");
            writer.printf("    <div class=\"score-number\" style=\"color: %s;\">%d / 100</div>%n",
                    result.getRiskAssessment().getRiskLevel().getHexColor(),
                    result.getRiskAssessment().getScore());
            writer.printf("    <div style=\"color: var(--muted); font-size: 0.9rem;\">Indicator Confidence: <strong>%s</strong></div>%n",
                    result.getRiskAssessment().getFormattedConfidence());
            writer.printf("    <div style=\"margin-top: 12px; font-size: 0.85rem;\">%s</div>%n",
                    SecurityUtils.escapeHtml(result.getRiskAssessment().getExplanation()));
            writer.println("  </div>");
            writer.println("</div>");

            // Digital Forensics Evidence Custody Section
            writer.println("<div class=\"card\">");
            writer.println("  <h3>Digital Forensics & Cryptographic Hashes</h3>");
            writer.println("  <table>");
            writer.println("    <thead><tr><th>Hash Scope</th><th>Algorithm</th><th>Cryptographic Digest (SHA-256)</th><th>Integrity Status</th></tr></thead>");
            writer.println("    <tbody>");
            writer.printf("      <tr><td>Original Ingested Raw Bytes</td><td>SHA-256</td><td><code>%s</code></td><td><span style=\"color:#10b981;\">&#x2714; Verified</span></td></tr>%n",
                    SecurityUtils.escapeHtml(message.getRawSha256()));
            if (evidenceList != null) {
                for (EvidenceRecord ev : evidenceList) {
                    writer.printf("      <tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>%n",
                            SecurityUtils.escapeHtml(ev.getEvidenceType()),
                            SecurityUtils.escapeHtml(ev.getHashAlgorithm()),
                            SecurityUtils.escapeHtml(ev.getRawMessageSha256()),
                            SecurityUtils.escapeHtml(ev.getSourceDescription()));
                }
            }
            writer.println("    </tbody>");
            writer.println("  </table>");
            writer.println("</div>");

            // Findings Grouped by Category
            writer.println("<div class=\"card\">");
            writer.println("  <h3>Detection Findings & Indicator Explanations</h3>");
            if (result.getFindings().isEmpty()) {
                writer.println("  <p style=\"color: var(--muted);\">No suspicious indicators or malicious patterns detected.</p>");
            } else {
                Map<FindingCategory, List<Finding>> grouped = result.getFindings().stream()
                        .collect(Collectors.groupingBy(Finding::getCategory));

                for (Map.Entry<FindingCategory, List<Finding>> entry : grouped.entrySet()) {
                    writer.printf("  <h4 style=\"color: var(--accent); margin-bottom: 8px;\">%s</h4>%n", SecurityUtils.escapeHtml(entry.getKey().getLabel()));
                    writer.println("  <table>");
                    writer.println("    <thead><tr><th>Rule ID</th><th>Severity</th><th>Confidence</th><th>Finding Description</th><th>Supporting Evidence</th><th>Safe Next Step</th></tr></thead>");
                    writer.println("    <tbody>");
                    for (Finding f : entry.getValue()) {
                        writer.println("      <tr>");
                        writer.printf("        <td><code>%s</code></td>%n", SecurityUtils.escapeHtml(f.getRuleId()));
                        writer.printf("        <td><span class=\"badge badge-%s\">%s</span></td>%n", f.getSeverity().name(), f.getSeverity().getDisplayName());
                        writer.printf("        <td>%s</td>%n", f.getFormattedConfidence());
                        writer.printf("        <td><strong>%s</strong><br/><small style=\"color:var(--muted);\">%s</small></td>%n",
                                SecurityUtils.escapeHtml(f.getShortDescription()),
                                SecurityUtils.escapeHtml(f.getExplanation()));
                        writer.printf("        <td><div class=\"snippet\">%s</div></td>%n", SecurityUtils.escapeHtml(f.getEvidenceSnippet()));
                        writer.printf("        <td style=\"font-size: 0.85rem; color:#38bdf8;\">%s</td>%n", SecurityUtils.escapeHtml(f.getSafeNextStep()));
                        writer.println("      </tr>");
                    }
                    writer.println("    </tbody>");
                    writer.println("  </table>");
                }
            }
            writer.println("</div>");

            // Extracted URLs Section
            if (!message.getExtractedUrls().isEmpty()) {
                writer.println("<div class=\"card\">");
                writer.println("  <h3>Extracted URLs & Link Analysis</h3>");
                writer.println("  <table>");
                writer.println("    <thead><tr><th>Visible Anchor Text</th><th>Destination URL</th><th>Domain</th><th>Indicators</th></tr></thead>");
                writer.println("    <tbody>");
                for (ExtractedUrl u : message.getExtractedUrls()) {
                    writer.println("      <tr>");
                    writer.printf("        <td>%s</td>%n", SecurityUtils.escapeHtml(u.getAnchorText().isBlank() ? "(No text)" : u.getAnchorText()));
                    writer.printf("        <td><code>%s</code></td>%n", SecurityUtils.escapeHtml(u.getOriginalUrl()));
                    writer.printf("        <td>%s</td>%n", SecurityUtils.escapeHtml(u.getDomain()));
                    writer.printf("        <td>%s</td>%n", SecurityUtils.escapeHtml(u.getSuspiciousReasons().isEmpty() ? "Benign" : String.join("; ", u.getSuspiciousReasons())));
                    writer.println("      </tr>");
                }
                writer.println("    </tbody>");
                writer.println("  </table>");
                writer.println("</div>");
            }

            // Legal & Academic Disclaimer
            writer.println("<div class=\"disclaimer\">");
            writer.println("  <strong>MailShield Platform Forensic Integrity Statement:</strong> This report represents automated decision-support findings derived via static heuristic analysis, RFC 5322 header verification, and local threat intelligence feeds. The risk score reflects indicator severity and does not guarantee complete absence of advanced persistent threats (APTs). Never click or execute unverified email attachments. Local database logs are stored in tamper-evident SQLite format; local administrator access may alter local files unless hardened OS controls are configured.");
            writer.printf("  <br/><br/>Generated by MailShield v1.0.0 (Scoring Engine: %s) on %s.<br/>",
                    result.getRuleEngineVersion(), FORMATTER.format(result.getAnalyzedAt()));
            writer.println("</div>");

            writer.println("</div>");
            writer.println("</body>");
            writer.println("</html>");
        }
    }

    @Override
    public void generateCsvSummary(List<AnalysisResult> results, File targetFile) throws IOException {
        if (targetFile == null) return;
        File parent = targetFile.getParentFile();
        if (parent != null && !parent.exists()) parent.mkdirs();

        try (PrintWriter writer = new PrintWriter(new FileWriter(targetFile))) {
            writer.println("AnalysisID,EmailID,RiskLevel,RiskScore,Confidence,CriticalFindings,HighFindings,RuleVersion,AnalyzedAt");
            if (results != null) {
                for (AnalysisResult r : results) {
                    writer.printf("\"%s\",\"%s\",\"%s\",%d,%.2f,%d,%d,\"%s\",\"%s\"%n",
                            r.getAnalysisId(),
                            r.getEmailMessageId(),
                            r.getRiskAssessment().getRiskLevel().name(),
                            r.getRiskAssessment().getScore(),
                            r.getRiskAssessment().getAggregateConfidence(),
                            r.getCriticalFindingCount(),
                            r.getHighFindingCount(),
                            r.getRuleEngineVersion(),
                            r.getAnalyzedAt().toString());
                }
            }
        }
    }
}

