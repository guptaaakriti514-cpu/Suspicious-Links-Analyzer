package com.mailshield.reporting;

import com.mailshield.model.AnalysisResult;
import com.mailshield.model.EmailMessage;
import com.mailshield.model.EvidenceRecord;
import com.mailshield.model.InvestigationCase;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * Service contract for generating professional cybersecurity investigation reports.
 */
public interface ReportGenerator {

    /**
     * Generate a standalone, secure, injection-resistant HTML forensic report.
     *
     * @param investigationCase Case record (optional)
     * @param message Email message
     * @param result Analysis result
     * @param evidenceList List of evidence records
     * @param targetFile Destination .html file
     * @throws IOException on write error
     */
    void generateHtmlReport(InvestigationCase investigationCase, EmailMessage message,
                            AnalysisResult result, List<EvidenceRecord> evidenceList,
                            File targetFile) throws IOException;

    /**
     * Generate a CSV summary export of cases or analyzed emails.
     *
     * @param results List of analysis results paired with emails
     * @param targetFile Destination .csv file
     * @throws IOException on write error
     */
    void generateCsvSummary(List<AnalysisResult> results, File targetFile) throws IOException;
}

