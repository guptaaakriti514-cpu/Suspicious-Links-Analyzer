package com.mailshield.ui;

import com.mailshield.model.*;
import com.mailshield.reporting.ReportGenerator;
import com.mailshield.storage.CaseRepository;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;

/**
 * Enterprise SOC Email Content & Digital Forensics Inspection Dialog.
 * Displays normalized headers, sanitized HTML & plaintext message bodies,
 * authentication badges (SPF/DKIM/DMARC), cryptographic SHA-256 custody digests,
 * extracted hyperlink mismatch analysis, attachment payloads, and threat findings.
 */
public class EmailDetailsDialog extends JDialog {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault());

    private final EmailMessage email;
    private final AnalysisResult analysisResult;
    private final ReportGenerator reportGenerator;
    private final CaseRepository caseRepository;

    public EmailDetailsDialog(Window parent, EmailMessage email, AnalysisResult analysisResult,
                              CaseRepository caseRepository, ReportGenerator reportGenerator) {
        super(parent, "SOC Email Threat Inspection — " + (email != null ? email.getSubject() : "Details"), ModalityType.APPLICATION_MODAL);
        this.email = email;
        this.analysisResult = analysisResult;
        this.caseRepository = caseRepository;
        this.reportGenerator = reportGenerator;

        setSize(1000, 750);
        setMinimumSize(new Dimension(840, 580));
        setLocationRelativeTo(parent);
        getContentPane().setBackground(UiTheme.BG_DARK);
        setLayout(new BorderLayout(0, 10));

        initHeader();
        initTabs();
        initFooter();
    }

    private void initHeader() {
        JPanel headerCard = UiTheme.createCardPanel();
        headerCard.setLayout(new BorderLayout(16, 8));

        // Top line: Subject and Risk Badges
        JPanel topLine = new JPanel(new BorderLayout(12, 0));
        topLine.setOpaque(false);

        JLabel lblSubject = new JLabel(email != null && !email.getSubject().isBlank() ? email.getSubject() : "(No Subject)");
        lblSubject.setFont(UiTheme.FONT_TITLE);
        lblSubject.setForeground(UiTheme.TEXT_PRIMARY);

        JPanel badgesPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        badgesPanel.setOpaque(false);

        RiskLevel riskLevel = analysisResult != null ? analysisResult.getRiskAssessment().getRiskLevel() : RiskLevel.LOW;
        int score = analysisResult != null ? analysisResult.getRiskAssessment().getScore() : 0;

        JLabel badgeRisk = UiTheme.createRiskBadge(riskLevel);
        JLabel lblScore = new JLabel(" Threat Score: " + score + "/100 ");
        lblScore.setFont(UiTheme.FONT_BOLD);
        lblScore.setForeground(UiTheme.TEXT_PRIMARY);
        lblScore.setOpaque(true);
        lblScore.setBackground(new Color(0x33, 0x41, 0x55));
        lblScore.setBorder(new EmptyBorder(2, 6, 2, 6));

        badgesPanel.add(lblScore);
        badgesPanel.add(badgeRisk);

        topLine.add(lblSubject, BorderLayout.CENTER);
        topLine.add(badgesPanel, BorderLayout.EAST);

        // Metadata Grid (2 columns)
        JPanel metaGrid = new JPanel(new GridLayout(3, 2, 16, 4));
        metaGrid.setOpaque(false);
        metaGrid.setBorder(new EmptyBorder(8, 0, 0, 0));

        String fromText = email != null ? email.getFrom() : "N/A";
        String dateText = email != null && email.getDate() != null ? TIME_FMT.format(email.getDate()) : "Unknown";
        String provText = email != null && email.getProviderSource() != null ? email.getProviderSource().getTitle() : "Direct Ingestion";
        String replyTo = email != null ? email.getReplyTo() : "";
        String sha256 = email != null && email.getRawSha256() != null ? email.getRawSha256() : "N/A";

        metaGrid.add(createMetaRow("Sender (From):", fromText, false));
        metaGrid.add(createMetaRow("Date / Ingested:", dateText, false));

        boolean replyMismatch = email != null && !replyTo.isBlank() && !email.getFromAddress().isBlank()
                && !replyTo.equalsIgnoreCase(email.getFromAddress());
        metaGrid.add(createMetaRow("Reply-To:", replyTo.isBlank() ? "(None specified)" : replyTo + (replyMismatch ? " [⚠ BEC SENDER MISMATCH]" : ""), replyMismatch));
        metaGrid.add(createMetaRow("Source Channel:", provText, false));

        metaGrid.add(createMetaRow("SHA-256 Custody:", sha256.length() > 32 ? sha256.substring(0, 32) + "..." : sha256, false));

        // Authentication Badges row
        AuthenticationResult auth = email != null ? email.getAuthResult() : null;
        String authSummary = "SPF: " + (auth != null && auth.getSpfStatus() != null ? auth.getSpfStatus().getDisplay() : "NONE") +
                "  |  DKIM: " + (auth != null && auth.getDkimStatus() != null ? auth.getDkimStatus().getDisplay() : "NONE") +
                "  |  DMARC: " + (auth != null && auth.getDmarcStatus() != null ? auth.getDmarcStatus().getDisplay() : "NONE");
        metaGrid.add(createMetaRow("Mail Auth:", authSummary, false));

        headerCard.add(topLine, BorderLayout.NORTH);
        headerCard.add(metaGrid, BorderLayout.CENTER);

        add(headerCard, BorderLayout.NORTH);
    }

    private JPanel createMetaRow(String label, String value, boolean isWarning) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        row.setOpaque(false);

        JLabel l = new JLabel(label);
        l.setFont(UiTheme.FONT_SMALL);
        l.setForeground(UiTheme.TEXT_MUTED);

        JLabel v = new JLabel(value);
        v.setFont(isWarning ? UiTheme.FONT_BOLD : UiTheme.FONT_REGULAR);
        v.setForeground(isWarning ? UiTheme.COLOR_CRITICAL : UiTheme.TEXT_PRIMARY);

        row.add(l);
        row.add(v);
        return row;
    }

    private void initTabs() {
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setBackground(UiTheme.BG_DARK);
        tabbedPane.setForeground(UiTheme.TEXT_PRIMARY);

        // Tab 1: Rendered HTML / Formatted Body
        tabbedPane.addTab("📄 Rendered Message Body", createRenderedBodyTab());

        // Tab 2: Plain Text Body
        tabbedPane.addTab("📝 Plain Text Content", createPlainTextTab());

        // Tab 3: Threat Findings & Indicators
        int findingCount = analysisResult != null && analysisResult.getFindings() != null ? analysisResult.getFindings().size() : 0;
        tabbedPane.addTab("🔍 Threat Findings (" + findingCount + ")", createFindingsTab());

        // Tab 4: Extracted Hyperlinks
        int urlCount = email != null && email.getExtractedUrls() != null ? email.getExtractedUrls().size() : 0;
        tabbedPane.addTab("🔗 Extracted Links (" + urlCount + ")", createUrlsTab());

        // Tab 5: Attachments & Payloads
        int attCount = email != null && email.getAttachments() != null ? email.getAttachments().size() : 0;
        tabbedPane.addTab("📎 Attachments (" + attCount + ")", createAttachmentsTab());

        // Tab 6: Raw RFC Headers
        tabbedPane.addTab("📋 Raw Headers", createHeadersTab());

        add(tabbedPane, BorderLayout.CENTER);
    }

    private JPanel createRenderedBodyTab() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(UiTheme.CARD_BG);
        panel.setBorder(new EmptyBorder(12, 14, 12, 14));

        String html = email != null ? email.getBodyHtml() : "";
        String text = email != null ? email.getBodyText() : "";

        if (html != null && !html.isBlank()) {
            JEditorPane editorPane = new JEditorPane();
            editorPane.setContentType("text/html");
            editorPane.setText(html);
            editorPane.setEditable(false);
            editorPane.setCaretPosition(0);
            editorPane.setBackground(new Color(0x13, 0x1B, 0x2E));
            editorPane.setForeground(UiTheme.TEXT_PRIMARY);

            JScrollPane scroll = new JScrollPane(editorPane);
            scroll.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
            panel.add(scroll, BorderLayout.CENTER);
        } else {
            JTextArea textArea = new JTextArea();
            textArea.setText(text != null && !text.isBlank() ? text : "(Empty email body)");
            textArea.setEditable(false);
            textArea.setLineWrap(true);
            textArea.setWrapStyleWord(true);
            textArea.setFont(UiTheme.FONT_REGULAR);
            textArea.setBackground(new Color(0x13, 0x1B, 0x2E));
            textArea.setForeground(UiTheme.TEXT_PRIMARY);
            textArea.setCaretPosition(0);

            JScrollPane scroll = new JScrollPane(textArea);
            scroll.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
            panel.add(scroll, BorderLayout.CENTER);
        }

        return panel;
    }

    private JPanel createPlainTextTab() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(UiTheme.CARD_BG);
        panel.setBorder(new EmptyBorder(12, 14, 12, 14));

        JTextArea textArea = new JTextArea();
        String text = email != null ? email.getBodyText() : "";
        textArea.setText(text != null && !text.isBlank() ? text : "(No plain text content available)");
        textArea.setEditable(false);
        textArea.setFont(UiTheme.FONT_MONO);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setBackground(new Color(0x13, 0x1B, 0x2E));
        textArea.setForeground(UiTheme.TEXT_PRIMARY);
        textArea.setCaretPosition(0);

        JScrollPane scroll = new JScrollPane(textArea);
        scroll.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createFindingsTab() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(UiTheme.CARD_BG);
        panel.setBorder(new EmptyBorder(12, 14, 12, 14));

        String[] cols = {"Severity", "Rule ID", "Category", "Detected Indicator Details", "Ceiling Weight"};
        DefaultTableModel model = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        if (analysisResult != null && analysisResult.getFindings() != null) {
            for (Finding f : analysisResult.getFindings()) {
                model.addRow(new Object[]{
                        f.getSeverity() != null ? f.getSeverity().name() : "INFO",
                        f.getRuleId() != null ? f.getRuleId() : "-",
                        f.getCategory() != null ? f.getCategory().name() : "-",
                        f.getShortDescription() != null ? f.getShortDescription() : "",
                        f.getSeverity() == Severity.CRITICAL ? "+35" : (f.getSeverity() == Severity.HIGH ? "+25" : "+10")
                });
            }
        }

        JTable table = new JTable(model);
        table.setRowHeight(26);
        table.setFont(UiTheme.FONT_REGULAR);
        table.getColumnModel().getColumn(0).setPreferredWidth(90);
        table.getColumnModel().getColumn(1).setPreferredWidth(100);
        table.getColumnModel().getColumn(2).setPreferredWidth(130);
        table.getColumnModel().getColumn(3).setPreferredWidth(450);
        table.getColumnModel().getColumn(4).setPreferredWidth(90);

        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createUrlsTab() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(UiTheme.CARD_BG);
        panel.setBorder(new EmptyBorder(12, 14, 12, 14));

        String[] cols = {"Anchor Text (Visible)", "Target Destination URL", "Host Domain", "Forensics Flags"};
        DefaultTableModel model = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        if (email != null && email.getExtractedUrls() != null) {
            for (ExtractedUrl u : email.getExtractedUrls()) {
                StringBuilder flags = new StringBuilder();
                if (u.isMismatchWithAnchor()) flags.append("[Anchor Mismatch] ");
                if (u.isIpHost()) flags.append("[Direct IP Host] ");
                if (u.hasHomograph() || u.isPunycode()) flags.append("[Homoglyph/Typosquat] ");
                if (!u.getScheme().equalsIgnoreCase("https") && !u.getScheme().equalsIgnoreCase("http")) flags.append("[Unsafe Scheme] ");
                if (flags.isEmpty()) flags.append("Clean / Standard Scheme");

                model.addRow(new Object[]{
                        u.getAnchorText() != null && !u.getAnchorText().isBlank() ? u.getAnchorText() : "(No anchor)",
                        u.getOriginalUrl(),
                        u.getDomain(),
                        flags.toString().trim()
                });
            }
        }

        JTable table = new JTable(model);
        table.setRowHeight(26);
        table.setFont(UiTheme.FONT_REGULAR);
        table.getColumnModel().getColumn(0).setPreferredWidth(180);
        table.getColumnModel().getColumn(1).setPreferredWidth(320);
        table.getColumnModel().getColumn(2).setPreferredWidth(160);
        table.getColumnModel().getColumn(3).setPreferredWidth(220);

        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createAttachmentsTab() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(UiTheme.CARD_BG);
        panel.setBorder(new EmptyBorder(12, 14, 12, 14));

        String[] cols = {"Filename", "Extension", "MIME Type", "Size", "Forensic Risk Flag"};
        DefaultTableModel model = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        if (email != null && email.getAttachments() != null) {
            for (EmailAttachmentMetadata a : email.getAttachments()) {
                String flag = a.isSuspicious() ? "⚠ HIGH RISK EXECUTABLE / SUSPICIOUS" : "Clean Metadata";
                String ext = "";
                int dot = a.getFilename().lastIndexOf('.');
                if (dot != -1) ext = a.getFilename().substring(dot);

                model.addRow(new Object[]{
                        a.getFilename(),
                        ext,
                        a.getContentType(),
                        a.getFormattedSize(),
                        flag
                });
            }
        }

        JTable table = new JTable(model);
        table.setRowHeight(26);
        table.setFont(UiTheme.FONT_REGULAR);
        table.getColumnModel().getColumn(0).setPreferredWidth(220);
        table.getColumnModel().getColumn(1).setPreferredWidth(90);
        table.getColumnModel().getColumn(2).setPreferredWidth(180);
        table.getColumnModel().getColumn(3).setPreferredWidth(100);
        table.getColumnModel().getColumn(4).setPreferredWidth(220);

        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createHeadersTab() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(UiTheme.CARD_BG);
        panel.setBorder(new EmptyBorder(12, 14, 12, 14));

        JTextArea textArea = new JTextArea();
        textArea.setFont(UiTheme.FONT_MONO);
        textArea.setEditable(false);
        textArea.setBackground(new Color(0x13, 0x1B, 0x2E));
        textArea.setForeground(UiTheme.TEXT_PRIMARY);

        StringBuilder sb = new StringBuilder();
        if (email != null && email.getHeaders() != null && !email.getHeaders().isEmpty()) {
            for (EmailHeader h : email.getHeaders()) {
                sb.append(h.getName()).append(": ").append(h.getValue()).append("\n");
            }
        } else {
            sb.append("Message-ID: ").append(email != null ? email.getMessageIdHeader() : "").append("\n");
            sb.append("From: ").append(email != null ? email.getFrom() : "").append("\n");
            sb.append("To: ").append(email != null ? String.join(", ", email.getTo()) : "").append("\n");
            sb.append("Subject: ").append(email != null ? email.getSubject() : "").append("\n");
            sb.append("Date: ").append(email != null && email.getDate() != null ? email.getDate().toString() : "").append("\n");
            sb.append("SHA-256 Digest: ").append(email != null ? email.getRawSha256() : "").append("\n");
        }

        textArea.setText(sb.toString());
        textArea.setCaretPosition(0);

        JScrollPane scroll = new JScrollPane(textArea);
        scroll.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    private void initFooter() {
        JPanel footer = new JPanel(new BorderLayout(12, 0));
        footer.setBackground(UiTheme.SIDEBAR_BG);
        footer.setBorder(new EmptyBorder(10, 16, 12, 16));

        // Left side: verdict explanation
        String rationale = analysisResult != null ? analysisResult.getRiskAssessment().getExplanation() : "Verdict: Analyzed and archived in local SOC repository.";
        JLabel lblRationale = new JLabel("<html><small style='color:#94a3b8;'><strong>SOC Verdict Rationale:</strong> " + rationale + "</small></html>");
        lblRationale.setFont(UiTheme.FONT_SMALL);

        // Right side: action buttons
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        btnPanel.setOpaque(false);

        JButton btnCopySha = UiTheme.createStyledButton("📋 Copy SHA-256", UiTheme.CARD_BG);
        btnCopySha.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnCopySha.addActionListener(e -> {
            if (email != null && email.getRawSha256() != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                        new StringSelection(email.getRawSha256()), null
                );
                JOptionPane.showMessageDialog(this,
                        "SHA-256 Digest copied to clipboard:\n\n" + email.getRawSha256(),
                        "Copied", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        JButton btnExportReport = UiTheme.createStyledButton("📊 Export HTML Report", UiTheme.ACCENT_BLUE);
        btnExportReport.addActionListener(e -> exportHtmlReport());

        JButton btnClose = UiTheme.createStyledButton("Close", UiTheme.CARD_BG);
        btnClose.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnClose.addActionListener(e -> dispose());

        btnPanel.add(btnCopySha);
        if (reportGenerator != null && analysisResult != null) {
            btnPanel.add(btnExportReport);
        }
        btnPanel.add(btnClose);

        footer.add(lblRationale, BorderLayout.CENTER);
        footer.add(btnPanel, BorderLayout.EAST);
        add(footer, BorderLayout.SOUTH);
    }

    private void exportHtmlReport() {
        if (reportGenerator == null || email == null || analysisResult == null) return;

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Save SOC Forensic Investigation Report");
        String sanitizedSub = email.getSubject().replaceAll("[^a-zA-Z0-9_-]", "_");
        fileChooser.setSelectedFile(new File("MailShield_Report_" + sanitizedSub + ".html"));

        int userSelection = fileChooser.showSaveDialog(this);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File target = fileChooser.getSelectedFile();
            if (!target.getName().toLowerCase().endsWith(".html")) {
                target = new File(target.getParentFile(), target.getName() + ".html");
            }

            try {
                List<EvidenceRecord> evidenceList = caseRepository != null ?
                        caseRepository.findEvidenceByEmailId(email.getId()) : Collections.emptyList();
                reportGenerator.generateHtmlReport(null, email, analysisResult, evidenceList, target);
                JOptionPane.showMessageDialog(this,
                        "HTML Forensic Investigation Report exported successfully:\n\n" + target.getAbsolutePath(),
                        "Report Exported", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Failed to export report: " + ex.getMessage(),
                        "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
