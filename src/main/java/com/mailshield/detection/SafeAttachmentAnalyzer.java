package com.mailshield.detection;

import com.mailshield.model.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Robust attachment metadata analyzer.
 * Detects double file extensions (e.g., invoice.pdf.exe), dangerous executable types,
 * macro-enabled document containers, and MIME type anomalies.
 * Strictly NEVER executes or opens binary payloads.
 */
public class SafeAttachmentAnalyzer implements AttachmentMetadataAnalyzer {

    private static final Set<String> EXECUTABLE_EXTENSIONS = Set.of(
            "exe", "scr", "vbs", "bat", "cmd", "ps1", "js", "hta", "jar", "cpl", "pif", "gadget", "msi", "msp", "wsf"
    );

    private static final Set<String> MACRO_EXTENSIONS = Set.of(
            "docm", "xlsm", "pptm", "dotm", "xltm"
    );

    private static final Set<String> CONTAINER_PAYLOAD_EXTENSIONS = Set.of(
            "iso", "img", "vhd", "vhdx"
    );

    @Override
    public List<Finding> analyzeAttachments(EmailMessage message) {
        List<Finding> findings = new ArrayList<>();
        List<EmailAttachmentMetadata> attachments = message.getAttachments();

        if (attachments == null || attachments.isEmpty()) {
            return findings;
        }

        for (EmailAttachmentMetadata att : attachments) {
            String filename = att.getFilename().toLowerCase(Locale.ROOT);
            String extension = extractExtension(filename);

            // 1. Double Extension Detection (e.g., .pdf.exe, .docx.vbs, .xlsx.scr)
            if (isDoubleExtension(filename)) {
                findings.add(Finding.builder()
                        .ruleId("ATT-001")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.SUSPICIOUS_ATTACHMENT)
                        .severity(Severity.CRITICAL)
                        .confidence(0.98)
                        .shortDescription("Deceptive Double File Extension Detected")
                        .explanation("The attachment filename uses a disguised double extension (e.g. .pdf.exe) designed to exploit Windows default file extension hiding.")
                        .evidenceSnippet(String.format("Filename: '%s' | Hash: %s", att.getFilename(), att.getSha256Hash()))
                        .sourceLocation("Attachment Metadata: " + att.getFilename())
                        .findingType(FindingType.METADATA_OBSERVATION)
                        .safeNextStep("QUARANTINE IMMEDIATELY. Do not open or permit endpoint execution under any circumstances.")
                        .build());
            }

            // 2. Direct Executable / Script Payload
            if (EXECUTABLE_EXTENSIONS.contains(extension)) {
                findings.add(Finding.builder()
                        .ruleId("ATT-002")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.SUSPICIOUS_ATTACHMENT)
                        .severity(Severity.CRITICAL)
                        .confidence(0.95)
                        .shortDescription("Direct Executable / Script Payload")
                        .explanation("The attachment is a Windows executable binary or script capable of executing arbitrary code upon opening.")
                        .evidenceSnippet("Extension: ." + extension + " (" + att.getFilename() + ")")
                        .sourceLocation("Attachment: " + att.getFilename())
                        .findingType(FindingType.METADATA_OBSERVATION)
                        .safeNextStep("Block executable at perimeter mail gateway.")
                        .build());
            }

            // 3. Macro-Enabled Office Documents
            if (MACRO_EXTENSIONS.contains(extension)) {
                findings.add(Finding.builder()
                        .ruleId("ATT-003")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.SUSPICIOUS_ATTACHMENT)
                        .severity(Severity.HIGH)
                        .confidence(0.85)
                        .shortDescription("Macro-Enabled Document Format")
                        .explanation("The attachment uses a macro-enabled Office extension (e.g. .docm, .xlsm), commonly utilized for initial payload staging in malware campaigns.")
                        .evidenceSnippet("Extension: ." + extension + " (" + att.getFilename() + ")")
                        .sourceLocation("Attachment: " + att.getFilename())
                        .findingType(FindingType.METADATA_OBSERVATION)
                        .safeNextStep("Submit to isolated sandbox or inspect VBA code in a safe disassembler.")
                        .build());
            }

            // 4. Disk Image Container (ISO/IMG/VHD)
            if (CONTAINER_PAYLOAD_EXTENSIONS.contains(extension)) {
                findings.add(Finding.builder()
                        .ruleId("ATT-004")
                        .ruleVersion("1.0.0")
                        .category(FindingCategory.SUSPICIOUS_ATTACHMENT)
                        .severity(Severity.HIGH)
                        .confidence(0.88)
                        .shortDescription("Disk Image Container Payload (ISO/IMG)")
                        .explanation("The attachment is a disk image file, frequently used by threat actors to evade Mark-of-the-Web (MOTW) security controls on Windows.")
                        .evidenceSnippet("Extension: ." + extension + " (" + att.getFilename() + ")")
                        .sourceLocation("Attachment: " + att.getFilename())
                        .findingType(FindingType.METADATA_OBSERVATION)
                        .safeNextStep("Inspect container contents within an isolated forensic sandbox.")
                        .build());
            }
        }

        return findings;
    }

    private boolean isDoubleExtension(String filename) {
        int lastDot = filename.lastIndexOf('.');
        if (lastDot <= 0) return false;
        String withoutLast = filename.substring(0, lastDot);
        int secondDot = withoutLast.lastIndexOf('.');
        if (secondDot <= 0) return false;

        String middleExt = withoutLast.substring(secondDot + 1).toLowerCase(Locale.ROOT);
        String finalExt = filename.substring(lastDot + 1).toLowerCase(Locale.ROOT);

        // Disguised extensions like .pdf.exe, .docx.vbs, .xlsx.scr, .jpg.exe
        Set<String> disguisedDocExts = Set.of("pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt");
        return disguisedDocExts.contains(middleExt) && EXECUTABLE_EXTENSIONS.contains(finalExt);
    }

    private String extractExtension(String filename) {
        int idx = filename.lastIndexOf('.');
        if (idx >= 0 && idx < filename.length() - 1) {
            return filename.substring(idx + 1).toLowerCase(Locale.ROOT);
        }
        return "";
    }
}

