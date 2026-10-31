package com.mailshield.detection;

import com.mailshield.model.EmailAttachmentMetadata;
import com.mailshield.model.EmailMessage;
import com.mailshield.model.Finding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class SafeAttachmentAnalyzerTest {

    private SafeAttachmentAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new SafeAttachmentAnalyzer();
    }

    @Test
    @DisplayName("Should detect disguised double file extensions")
    void testDoubleExtensionDetection() {
        EmailAttachmentMetadata att = new EmailAttachmentMetadata(
                "Remittance_Advice.pdf.exe",
                "application/octet-stream",
                45000,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                false, ""
        );

        EmailMessage msg = EmailMessage.builder()
                .attachments(List.of(att))
                .build();

        List<Finding> findings = analyzer.analyzeAttachments(msg);
        assertThat(findings).anyMatch(f -> f.getRuleId().equals("ATT-001"));
    }

    @Test
    @DisplayName("Should detect direct Windows script executable payload")
    void testScriptExecutableDetection() {
        EmailAttachmentMetadata att = new EmailAttachmentMetadata(
                "invoice.vbs",
                "text/vbscript",
                12000,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                false, ""
        );

        EmailMessage msg = EmailMessage.builder()
                .attachments(List.of(att))
                .build();

        List<Finding> findings = analyzer.analyzeAttachments(msg);
        assertThat(findings).anyMatch(f -> f.getRuleId().equals("ATT-002"));
    }

    @Test
    @DisplayName("Should detect macro-enabled documents")
    void testMacroDocumentDetection() {
        EmailAttachmentMetadata att = new EmailAttachmentMetadata(
                "PurchaseOrder.docm",
                "application/vnd.ms-word.document.macroEnabled.12",
                65000,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                false, ""
        );

        EmailMessage msg = EmailMessage.builder()
                .attachments(List.of(att))
                .build();

        List<Finding> findings = analyzer.analyzeAttachments(msg);
        assertThat(findings).anyMatch(f -> f.getRuleId().equals("ATT-003"));
    }

    @Test
    @DisplayName("Should pass legitimate benign PDF documents")
    void testBenignPdfDocument() {
        EmailAttachmentMetadata att = new EmailAttachmentMetadata(
                "Quarterly_Report.pdf",
                "application/pdf",
                125000,
                "abc123hash",
                false, ""
        );

        EmailMessage msg = EmailMessage.builder()
                .attachments(List.of(att))
                .build();

        List<Finding> findings = analyzer.analyzeAttachments(msg);
        assertThat(findings).isEmpty();
    }
}

