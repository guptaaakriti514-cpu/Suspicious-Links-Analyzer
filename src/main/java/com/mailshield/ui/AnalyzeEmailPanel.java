package com.mailshield.ui;

import com.mailshield.app.DemoDataFixtures;
import com.mailshield.detection.DetectionEngine;
import com.mailshield.forensics.EvidenceManager;
import com.mailshield.ingestion.EmailParser;
import com.mailshield.model.*;
import com.mailshield.reporting.ReportGenerator;
import com.mailshield.storage.CaseRepository;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.time.Instant;
import java.util.List;

/**
 * Screen 2: Deep Email Threat Detection & Forensics Analysis.
 * Supports manual pasting of RFC 5322 text, .eml file import, and 1-click synthetic demo fixtures.
 */
public class AnalyzeEmailPanel extends JPanel {

    private final EmailParser emailParser;
    private final DetectionEngine detectionEngine;
    private final CaseRepository caseRepository;
    private final EvidenceManager evidenceManager;
    private final ReportGenerator reportGenerator;

    private JTextArea txtInputEmail;
    private JComboBox<DemoDataFixtures.EmailFixtureItem> cmbFixtures;
    private JButton btnAnalyze;
    private JButton btnImportEml;
    private JButton btnLoadFixture;
    private JProgressBar progressBar;

    // Results Display Components
    private JPanel resultsContainer;
    private JLabel lblRiskBadge;
    private JLabel lblScoreValue;
    private JLabel lblConfidenceValue;
    private JTextArea txtScoreExplanation;
    private JLabel lblAuthResults;
    private DefaultTableModel findingsTableModel;
    private DefaultTableModel urlsTableModel;
    private DefaultTableModel attachmentsTableModel;

    private JButton btnSaveCase;
    private JButton btnExportReport;

    private EmailMessage currentMessage;
    private AnalysisResult currentResult;

    public AnalyzeEmailPanel(EmailParser emailParser, DetectionEngine detectionEngine,
                             CaseRepository caseRepository, EvidenceManager evidenceManager,
                             ReportGenerator reportGenerator) {
        this.emailParser = emailParser;
        this.detectionEngine = detectionEngine;
        this.caseRepository = caseRepository;
        this.evidenceManager = evidenceManager;
        this.reportGenerator = reportGenerator;

        setLayout(new BorderLayout(16, 16));
        setBackground(UiTheme.BG_DARK);
        setBorder(new EmptyBorder(16, 20, 16, 20));

        initHeader();
        initSplitWorkspace();
    }

    private void initHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);

        JLabel title = new JLabel("Deep Email Ingestion, Static Analysis & Indicators");
        title.setFont(UiTheme.FONT_TITLE);

        JLabel subtitle = new JLabel("Inspect raw RFC 5322 email headers, multipart bodies, anchor hyperlinks, and attachment payloads");
        subtitle.setFont(UiTheme.FONT_SMALL);
        subtitle.setForeground(UiTheme.TEXT_MUTED);

        JPanel text = new JPanel(new GridLayout(2, 1, 0, 4));
        text.setOpaque(false);
        text.add(title);
        text.add(subtitle);

        // One-Click Demo Mode Controls
        JPanel demoBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        demoBar.setOpaque(false);

        JLabel lblFixture = new JLabel("Viva Demo Scenarios:");
        lblFixture.setFont(UiTheme.FONT_SMALL);
        lblFixture.setForeground(UiTheme.ACCENT_CYAN);

        cmbFixtures = new JComboBox<>(DemoDataFixtures.getAvailableFixtures().toArray(new DemoDataFixtures.EmailFixtureItem[0]));
        cmbFixtures.setPreferredSize(new Dimension(340, 30));

        btnLoadFixture = UiTheme.createStyledButton("Load Scenario", UiTheme.CARD_BG);
        btnLoadFixture.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnLoadFixture.addActionListener(e -> {
            DemoDataFixtures.EmailFixtureItem item = (DemoDataFixtures.EmailFixtureItem) cmbFixtures.getSelectedItem();
            if (item != null) {
                txtInputEmail.setText(item.getRawContent());
                runAnalysis();
            }
        });

        demoBar.add(lblFixture);
        demoBar.add(cmbFixtures);
        demoBar.add(btnLoadFixture);

        header.add(text, BorderLayout.WEST);
        header.add(demoBar, BorderLayout.EAST);
        add(header, BorderLayout.NORTH);
    }

    private void initSplitWorkspace() {
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.42);
        splitPane.setBorder(null);
        splitPane.setOpaque(false);

        // Left Panel: Input & Controls
        JPanel leftPanel = UiTheme.createCardPanel();
        leftPanel.setLayout(new BorderLayout(0, 10));

        JPanel leftHeader = new JPanel(new BorderLayout());
        leftHeader.setOpaque(false);
        JLabel inputTitle = new JLabel("Raw Email Input (Headers & Body)");
        inputTitle.setFont(UiTheme.FONT_HEADER);

        btnImportEml = UiTheme.createStyledButton("Import .EML File", UiTheme.CARD_BG);
        btnImportEml.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnImportEml.addActionListener(e -> importEmlFile());

        leftHeader.add(inputTitle, BorderLayout.WEST);
        leftHeader.add(btnImportEml, BorderLayout.EAST);
        leftPanel.add(leftHeader, BorderLayout.NORTH);

        txtInputEmail = new JTextArea();
        txtInputEmail.setFont(UiTheme.FONT_MONO);
        txtInputEmail.setLineWrap(true);
        txtInputEmail.setWrapStyleWord(true);
        JScrollPane scrollInput = new JScrollPane(txtInputEmail);
        scrollInput.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        leftPanel.add(scrollInput, BorderLayout.CENTER);

        // Bottom Action Bar
        JPanel leftFooter = new JPanel(new BorderLayout(8, 8));
        leftFooter.setOpaque(false);

        progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        progressBar.setVisible(false);

        btnAnalyze = UiTheme.createStyledButton("⚡ Run Threat & Forensic Analysis", UiTheme.ACCENT_BLUE);
        btnAnalyze.setPreferredSize(new Dimension(0, 36));
        btnAnalyze.addActionListener(e -> runAnalysis());

        leftFooter.add(progressBar, BorderLayout.NORTH);
        leftFooter.add(btnAnalyze, BorderLayout.SOUTH);
        leftPanel.add(leftFooter, BorderLayout.SOUTH);

        // Right Panel: Analysis Results & Findings
        resultsContainer = new JPanel(new BorderLayout(0, 12));
        resultsContainer.setOpaque(false);
        initResultsComponents();

        splitPane.setLeftComponent(leftPanel);
        splitPane.setRightComponent(resultsContainer);
        add(splitPane, BorderLayout.CENTER);
    }

    private void initResultsComponents() {
        // Summary Card at top of results
        JPanel summaryCard = UiTheme.createCardPanel();
        summaryCard.setLayout(new BorderLayout(12, 10));

        JPanel topVerdict = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        topVerdict.setOpaque(false);

        lblRiskBadge = UiTheme.createRiskBadge(RiskLevel.INSUFFICIENT_DATA);
        lblScoreValue = new JLabel("Score: -- / 100");
        lblScoreValue.setFont(UiTheme.FONT_HEADER);
        lblConfidenceValue = new JLabel("Confidence: --");
        lblConfidenceValue.setFont(UiTheme.FONT_SMALL);
        lblConfidenceValue.setForeground(UiTheme.TEXT_MUTED);

        topVerdict.add(lblRiskBadge);
        topVerdict.add(lblScoreValue);
        topVerdict.add(lblConfidenceValue);
        summaryCard.add(topVerdict, BorderLayout.NORTH);

        txtScoreExplanation = new JTextArea("Ready to analyze. Paste email headers or load a demo fixture to begin.");
        txtScoreExplanation.setWrapStyleWord(true);
        txtScoreExplanation.setLineWrap(true);
        txtScoreExplanation.setEditable(false);
        txtScoreExplanation.setFont(UiTheme.FONT_REGULAR);
        txtScoreExplanation.setBackground(UiTheme.CARD_BG);
        txtScoreExplanation.setBorder(null);
        summaryCard.add(txtScoreExplanation, BorderLayout.CENTER);

        lblAuthResults = new JLabel("Authentication: SPF: Unknown | DKIM: Unknown | DMARC: Unknown");
        lblAuthResults.setFont(UiTheme.FONT_SMALL);
        lblAuthResults.setForeground(UiTheme.ACCENT_CYAN);
        summaryCard.add(lblAuthResults, BorderLayout.SOUTH);

        resultsContainer.add(summaryCard, BorderLayout.NORTH);

        // Tabbed Pane for Findings, URLs, Attachments
        JTabbedPane tabbedPane = new JTabbedPane();

        // Tab 1: Findings Table
        String[] findingCols = {"Sev", "Rule ID", "Category", "Description", "Supporting Evidence", "Safe Action"};
        findingsTableModel = new DefaultTableModel(findingCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable tblFindings = new JTable(findingsTableModel);
        tblFindings.setRowHeight(26);
        tblFindings.getColumnModel().getColumn(0).setPreferredWidth(60);
        tblFindings.getColumnModel().getColumn(1).setPreferredWidth(80);
        tblFindings.getColumnModel().getColumn(2).setPreferredWidth(120);
        tblFindings.getColumnModel().getColumn(3).setPreferredWidth(180);
        tblFindings.getColumnModel().getColumn(4).setPreferredWidth(200);
        tblFindings.getColumnModel().getColumn(5).setPreferredWidth(200);
        JScrollPane scrollFindings = new JScrollPane(tblFindings);
        scrollFindings.setBorder(null);
        tabbedPane.addTab("Detection Findings", scrollFindings);

        // Tab 2: URLs Table
        String[] urlCols = {"Anchor Text", "Destination URL", "Domain", "Flags"};
        urlsTableModel = new DefaultTableModel(urlCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable tblUrls = new JTable(urlsTableModel);
        tblUrls.setRowHeight(26);
        JScrollPane scrollUrls = new JScrollPane(tblUrls);
        scrollUrls.setBorder(null);
        tabbedPane.addTab("Extracted URLs", scrollUrls);

        // Tab 3: Attachments Table
        String[] attCols = {"Filename", "MIME Type", "Size", "SHA-256 Hash", "Flags"};
        attachmentsTableModel = new DefaultTableModel(attCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable tblAtt = new JTable(attachmentsTableModel);
        tblAtt.setRowHeight(26);
        JScrollPane scrollAtt = new JScrollPane(tblAtt);
        scrollAtt.setBorder(null);
        tabbedPane.addTab("Attachments Metadata", scrollAtt);

        resultsContainer.add(tabbedPane, BorderLayout.CENTER);

        // Bottom Action Controls
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        actionRow.setOpaque(false);

        btnSaveCase = UiTheme.createStyledButton("Save as Incident Case", UiTheme.CARD_BG);
        btnSaveCase.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnSaveCase.setEnabled(false);
        btnSaveCase.addActionListener(e -> saveAsCase());

        btnExportReport = UiTheme.createStyledButton("Export Forensic Report (HTML)", UiTheme.ACCENT_CYAN);
        btnExportReport.setEnabled(false);
        btnExportReport.addActionListener(e -> exportHtmlReport());

        actionRow.add(btnSaveCase);
        actionRow.add(btnExportReport);
        resultsContainer.add(actionRow, BorderLayout.SOUTH);
    }

    private void runAnalysis() {
        String rawText = txtInputEmail.getText();
        if (rawText == null || rawText.isBlank()) {
            JOptionPane.showMessageDialog(this, "Please paste an email or load a scenario fixture first.", "Input Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        btnAnalyze.setEnabled(false);
        progressBar.setVisible(true);

        SwingWorker<AnalysisResult, Void> worker = new SwingWorker<>() {
            private EmailMessage parsedMessage;

            @Override
            protected AnalysisResult doInBackground() throws Exception {
                parsedMessage = emailParser.parseRawText(rawText);
                return detectionEngine.analyzeEmail(parsedMessage);
            }

            @Override
            protected void done() {
                try {
                    currentResult = get();
                    currentMessage = parsedMessage;
                    displayResults(currentMessage, currentResult);
                    btnSaveCase.setEnabled(true);
                    btnExportReport.setEnabled(true);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(AnalyzeEmailPanel.this,
                            "Analysis Error: " + ex.getMessage(), "Parser / Engine Error", JOptionPane.ERROR_MESSAGE);
                } finally {
                    btnAnalyze.setEnabled(true);
                    progressBar.setVisible(false);
                }
            }
        };
        worker.execute();
    }

    private void displayResults(EmailMessage msg, AnalysisResult res) {
        RiskAssessment risk = res.getRiskAssessment();

        // Update badge and score
        resultsContainer.remove(0);
        JPanel summaryCard = UiTheme.createCardPanel();
        summaryCard.setLayout(new BorderLayout(12, 10));

        JPanel topVerdict = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        topVerdict.setOpaque(false);
        lblRiskBadge = UiTheme.createRiskBadge(risk.getRiskLevel());
        lblScoreValue = new JLabel("Score: " + risk.getScore() + " / 100");
        lblScoreValue.setFont(UiTheme.FONT_HEADER);
        lblScoreValue.setForeground(risk.getRiskLevel() == RiskLevel.CRITICAL ? UiTheme.COLOR_CRITICAL :
                risk.getRiskLevel() == RiskLevel.HIGH ? UiTheme.COLOR_HIGH :
                risk.getRiskLevel() == RiskLevel.MEDIUM ? UiTheme.COLOR_MEDIUM : UiTheme.COLOR_LOW);

        lblConfidenceValue = new JLabel("Confidence: " + risk.getFormattedConfidence());
        lblConfidenceValue.setFont(UiTheme.FONT_SMALL);
        lblConfidenceValue.setForeground(UiTheme.TEXT_MUTED);

        topVerdict.add(lblRiskBadge);
        topVerdict.add(lblScoreValue);
        topVerdict.add(lblConfidenceValue);
        summaryCard.add(topVerdict, BorderLayout.NORTH);

        txtScoreExplanation.setText(risk.getExplanation());
        summaryCard.add(txtScoreExplanation, BorderLayout.CENTER);

        lblAuthResults.setText("Authentication: " + msg.getAuthResult().toString());
        summaryCard.add(lblAuthResults, BorderLayout.SOUTH);

        resultsContainer.add(summaryCard, BorderLayout.NORTH, 0);

        // Populate Findings Table
        findingsTableModel.setRowCount(0);
        for (Finding f : res.getFindings()) {
            findingsTableModel.addRow(new Object[]{
                    f.getSeverity().name(),
                    f.getRuleId(),
                    f.getCategory().getLabel(),
                    f.getShortDescription(),
                    f.getEvidenceSnippet(),
                    f.getSafeNextStep()
            });
        }

        // Populate URLs Table
        urlsTableModel.setRowCount(0);
        for (ExtractedUrl u : msg.getExtractedUrls()) {
            urlsTableModel.addRow(new Object[]{
                    u.getAnchorText().isBlank() ? "(None)" : u.getAnchorText(),
                    u.getOriginalUrl(),
                    u.getDomain(),
                    u.getSuspiciousReasons().isEmpty() ? "Benign" : String.join(", ", u.getSuspiciousReasons())
            });
        }

        // Populate Attachments Table
        attachmentsTableModel.setRowCount(0);
        for (EmailAttachmentMetadata att : msg.getAttachments()) {
            attachmentsTableModel.addRow(new Object[]{
                    att.getFilename(),
                    att.getContentType(),
                    att.getFormattedSize(),
                    att.getSha256Hash(),
                    att.isSuspicious() ? att.getSuspiciousReason() : "Verified"
            });
        }

        revalidate();
        repaint();
    }

    private void importEmlFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select RFC 5322 .EML File");
        int res = chooser.showOpenDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File selectedFile = chooser.getSelectedFile();
            try (FileInputStream fis = new FileInputStream(selectedFile)) {
                EmailMessage parsed = emailParser.parseEmlStream(fis, selectedFile.getName());
                txtInputEmail.setText(new String(parsed.getRawBytes()));
                runAnalysis();
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Failed to import EML file: " + e.getMessage(), "Import Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void saveAsCase() {
        if (currentMessage == null || currentResult == null) return;

        String caseId = "CASE-" + System.currentTimeMillis();
        String title = "Incident: " + currentMessage.getSubject();

        InvestigationCase c = InvestigationCase.builder()
                .caseId(caseId)
                .title(title)
                .status(CaseStatus.OPEN)
                .priority(currentResult.getRiskAssessment().getRiskLevel() == RiskLevel.CRITICAL ? CasePriority.CRITICAL :
                         currentResult.getRiskAssessment().getRiskLevel() == RiskLevel.HIGH ? CasePriority.HIGH : CasePriority.MEDIUM)
                .createdAt(Instant.now())
                .analystNotes("Imported and analyzed in MailShield. Initial risk score: " + currentResult.getRiskAssessment().getScore() + "/100")
                .associatedMessageIds(List.of(currentMessage.getId()))
                .analysisResultIds(List.of(currentResult.getAnalysisId()))
                .tags(List.of("ManualInvestigation", currentResult.getRiskAssessment().getRiskLevel().name()))
                .build();

        if (caseRepository != null) {
            caseRepository.saveEmailMessage(currentMessage);
            caseRepository.saveAnalysisResult(currentResult);
            caseRepository.saveCase(c);
        }
        if (evidenceManager != null) {
            evidenceManager.recordEvidence(currentMessage, caseId, "Incident Case Ingestion");
        }

        JOptionPane.showMessageDialog(this, "Investigation case saved successfully with ID: " + caseId,
                "Case Saved", JOptionPane.INFORMATION_MESSAGE);
    }

    private void exportHtmlReport() {
        if (currentMessage == null || currentResult == null) return;

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("MailShield_Report_" + currentMessage.getId().substring(0, 8) + ".html"));
        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File target = chooser.getSelectedFile();
            try {
                var evidenceList = evidenceManager != null ? evidenceManager.getEvidenceForCase("") : List.<EvidenceRecord>of();
                reportGenerator.generateHtmlReport(null, currentMessage, currentResult, evidenceList, target);
                JOptionPane.showMessageDialog(this, "HTML Forensic Report exported successfully to:\n" + target.getAbsolutePath(),
                        "Report Exported", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Report generation failed: " + e.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}

