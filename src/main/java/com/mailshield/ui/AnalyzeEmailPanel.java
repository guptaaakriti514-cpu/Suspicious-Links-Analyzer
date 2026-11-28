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
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileInputStream;
import java.time.Instant;
import java.util.List;

/**
 * Screen 2: Deep Email Threat Detection & Forensics Analysis.
 * Provides deep inspection of RFC 5322 emails, unique message IDs, cryptographic SHA-256 hashes,
 * full header attributes, authentication verdicts (SPF/DKIM/DMARC), extracted links, and explainable findings.
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
    private JTabbedPane tabbedPane;

    // Top Verdict & Forensic Header
    private JLabel lblRiskBadge;
    private JLabel lblScoreValue;
    private JLabel lblConfidenceValue;
    private JLabel lblStatusNotice;
    private JTextArea txtScoreExplanation;

    // Unique ID & Envelope Forensic Elements
    private JLabel lblUniqueMessageId;
    private JLabel lblSha256;
    private JLabel lblInternalId;
    private JLabel lblSubject;
    private JLabel lblFrom;
    private JLabel lblTo;
    private JLabel lblSenderDomain;
    private JLabel lblReturnPath;
    private JLabel lblDate;
    private JLabel lblAuthResults;

    // Table Models
    private DefaultTableModel findingsTableModel;
    private DefaultTableModel urlsTableModel;
    private DefaultTableModel headersTableModel;
    private DefaultTableModel attachmentsTableModel;

    // Body Views
    private JTextArea txtBodyText;
    private JTextArea txtBodyHtml;

    // Filter for Headers Table
    private TableRowSorter<DefaultTableModel> headerSorter;
    private JTextField txtHeaderFilter;

    // Action Controls
    private JButton btnSaveCase;
    private JButton btnExportReport;
    private JButton btnCopySummary;

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

        JLabel subtitle = new JLabel("Inspect raw RFC 5322 email headers, Unique Message-IDs, authentication status, links, and threat indicators");
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
        cmbFixtures.setPreferredSize(new Dimension(320, 30));

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
        splitPane.setResizeWeight(0.38);
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
        txtInputEmail.setText("""
boundary="57b587ac9083587e928d356703010158ec2a0d0c3ce145cf18c7c7ee1"
Subject: Be the engineer who cuts AI costs
From: Javier Canales <newsletter@mail.roadmap.sh>
To: guptaaakriti514@gmail.com
Feedback-Id: 28405721:21215182:152468:iterable
List-Unsubscribe: <https://links.iterable.com/s/uh/DC1baJt20nKmzPjcdINZ23BfoKSLVzzEPVXnVG0pcwpmkzxnlIdrvGVEMk7LafCXGwSQ59KrxJpFAUVJoplt_xhuh78tNevucWf4aySx0L-aFG5-k-nMSU6cxjZbOPQCw_jh-qSglMiNu9F3QHY0lZxZZYLccGirOQdMTaXvUnJ698-Kngk7b-AA4sty_rUqCp_PRPrm-q5Gj3/YbHUGGYikMrO6K6kvHs5ubNL.DgM827Iw/26>, <mailto:unsubscribe+21215182+28405721@unsubscribe.iterable.com>
X-Campaign-Id: 21215182
List-Unsubscribe-Post: List-Unsubscribe=One-Click
Return-Path: bounces@mail.roadmap.sh
X-Feedback-Id: 28405721:21215182:152468:iterable
Reply-To: newsletter@mail.roadmap.sh
X-Message-Id: 685fc92a5a544291a20d1e72d66a84e7
Message Id: <20261125170017.a63240896adfde77@mail.roadmap.sh>
Authentication-Results: mx.google.com; spf=pass (google.com: domain of bounces@mail.roadmap.sh designates 198.2.186.26 as permitted sender) smtp.mailfrom=bounces@mail.roadmap.sh; dkim=pass header.i=@mail.roadmap.sh header.s=k1 header.b=abcdef; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=mail.roadmap.sh

Hey there! Here is how to drastically reduce AI inference costs without losing precision...
Check our benchmarks here: https://roadmap.sh/ai-cost-reduction
        """);
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
        btnAnalyze.setPreferredSize(new Dimension(0, 38));
        btnAnalyze.addActionListener(e -> runAnalysis());

        leftFooter.add(progressBar, BorderLayout.NORTH);
        leftFooter.add(btnAnalyze, BorderLayout.SOUTH);
        leftPanel.add(leftFooter, BorderLayout.SOUTH);

        // Right Panel: Analysis Results & Findings
        resultsContainer = new JPanel(new BorderLayout(0, 10));
        resultsContainer.setOpaque(false);
        initResultsComponents();

        splitPane.setLeftComponent(leftPanel);
        splitPane.setRightComponent(resultsContainer);
        add(splitPane, BorderLayout.CENTER);
    }

    private void initResultsComponents() {
        // Summary & Forensic Identification Card at top of results
        JPanel summaryCard = buildForensicSummaryCard();
        resultsContainer.add(summaryCard, BorderLayout.NORTH);

        // Tabbed Pane for Findings, URLs, Headers, Attachments, Body
        tabbedPane = new JTabbedPane();

        // Tab 1: Findings Table
        String[] findingCols = {"Sev", "Rule ID", "Category", "Description", "Supporting Evidence", "Safe Action"};
        findingsTableModel = new DefaultTableModel(findingCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable tblFindings = new JTable(findingsTableModel);
        tblFindings.setRowHeight(26);
        tblFindings.getColumnModel().getColumn(0).setPreferredWidth(65);
        tblFindings.getColumnModel().getColumn(1).setPreferredWidth(85);
        tblFindings.getColumnModel().getColumn(2).setPreferredWidth(130);
        tblFindings.getColumnModel().getColumn(3).setPreferredWidth(210);
        tblFindings.getColumnModel().getColumn(4).setPreferredWidth(220);
        tblFindings.getColumnModel().getColumn(5).setPreferredWidth(200);

        // Custom Cell Renderer for Severity Column
        tblFindings.getColumnModel().getColumn(0).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                JLabel lbl = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                lbl.setHorizontalAlignment(SwingConstants.CENTER);
                lbl.setFont(UiTheme.FONT_BOLD);
                String val = value != null ? value.toString() : "";
                if (val.equalsIgnoreCase("CRITICAL")) {
                    lbl.setForeground(UiTheme.COLOR_CRITICAL);
                } else if (val.equalsIgnoreCase("HIGH")) {
                    lbl.setForeground(UiTheme.COLOR_HIGH);
                } else if (val.equalsIgnoreCase("MEDIUM")) {
                    lbl.setForeground(UiTheme.COLOR_MEDIUM);
                } else if (val.equalsIgnoreCase("LOW")) {
                    lbl.setForeground(UiTheme.COLOR_LOW);
                } else {
                    lbl.setForeground(UiTheme.ACCENT_CYAN);
                }
                return lbl;
            }
        });

        JScrollPane scrollFindings = new JScrollPane(tblFindings);
        scrollFindings.setBorder(null);
        tabbedPane.addTab("Detection Findings & Audit (0)", scrollFindings);

        // Tab 2: URLs Table
        String[] urlCols = {"Anchor Text", "Destination URL", "Domain", "Flags / Status"};
        urlsTableModel = new DefaultTableModel(urlCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable tblUrls = new JTable(urlsTableModel);
        tblUrls.setRowHeight(26);
        tblUrls.getColumnModel().getColumn(0).setPreferredWidth(120);
        tblUrls.getColumnModel().getColumn(1).setPreferredWidth(320);
        tblUrls.getColumnModel().getColumn(2).setPreferredWidth(150);
        tblUrls.getColumnModel().getColumn(3).setPreferredWidth(140);
        JScrollPane scrollUrls = new JScrollPane(tblUrls);
        scrollUrls.setBorder(null);
        tabbedPane.addTab("Extracted URLs (0)", scrollUrls);

        // Tab 3: All Parsed Headers Table (NEW: Allows inspecting every single RFC 5322 header)
        JPanel headersPanel = new JPanel(new BorderLayout(0, 6));
        headersPanel.setOpaque(false);

        JPanel headerFilterBar = new JPanel(new BorderLayout(8, 0));
        headerFilterBar.setOpaque(false);
        headerFilterBar.setBorder(new EmptyBorder(4, 4, 4, 4));
        JLabel lblFilter = new JLabel("Search Headers:");
        lblFilter.setFont(UiTheme.FONT_SMALL);
        lblFilter.setForeground(UiTheme.TEXT_MUTED);

        txtHeaderFilter = new JTextField();
        txtHeaderFilter.putClientProperty("JTextField.placeholderText", "Filter headers (e.g. message-id, spf, dkim, return-path, to)...");
        txtHeaderFilter.setFont(UiTheme.FONT_REGULAR);
        txtHeaderFilter.addCaretListener(e -> {
            String filterText = txtHeaderFilter.getText().trim();
            if (headerSorter != null) {
                if (filterText.isEmpty()) {
                    headerSorter.setRowFilter(null);
                } else {
                    headerSorter.setRowFilter(RowFilter.regexFilter("(?i)" + filterText));
                }
            }
        });
        headerFilterBar.add(lblFilter, BorderLayout.WEST);
        headerFilterBar.add(txtHeaderFilter, BorderLayout.CENTER);
        headersPanel.add(headerFilterBar, BorderLayout.NORTH);

        String[] headerCols = {"Header Field Name", "Header Value"};
        headersTableModel = new DefaultTableModel(headerCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable tblHeaders = new JTable(headersTableModel);
        tblHeaders.setRowHeight(24);
        tblHeaders.getColumnModel().getColumn(0).setPreferredWidth(180);
        tblHeaders.getColumnModel().getColumn(1).setPreferredWidth(520);
        tblHeaders.setFont(UiTheme.FONT_MONO);
        headerSorter = new TableRowSorter<>(headersTableModel);
        tblHeaders.setRowSorter(headerSorter);

        JScrollPane scrollHeaders = new JScrollPane(tblHeaders);
        scrollHeaders.setBorder(null);
        headersPanel.add(scrollHeaders, BorderLayout.CENTER);
        tabbedPane.addTab("Email Headers & Attributes (0)", headersPanel);

        // Tab 4: Attachments Table
        String[] attCols = {"Filename", "MIME Type", "Size", "SHA-256 Hash", "Security Verdict"};
        attachmentsTableModel = new DefaultTableModel(attCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable tblAtt = new JTable(attachmentsTableModel);
        tblAtt.setRowHeight(26);
        tblAtt.getColumnModel().getColumn(0).setPreferredWidth(160);
        tblAtt.getColumnModel().getColumn(1).setPreferredWidth(140);
        tblAtt.getColumnModel().getColumn(2).setPreferredWidth(90);
        tblAtt.getColumnModel().getColumn(3).setPreferredWidth(260);
        tblAtt.getColumnModel().getColumn(4).setPreferredWidth(150);
        JScrollPane scrollAtt = new JScrollPane(tblAtt);
        scrollAtt.setBorder(null);
        tabbedPane.addTab("Attachments Metadata (0)", scrollAtt);

        // Tab 5: Extracted Body Content View
        JPanel bodyPanel = new JPanel(new GridLayout(2, 1, 0, 8));
        bodyPanel.setOpaque(false);

        JPanel pnlPlainText = new JPanel(new BorderLayout(0, 4));
        pnlPlainText.setOpaque(false);
        JLabel lblPlainTitle = new JLabel("Parsed Plain Text Body:");
        lblPlainTitle.setFont(UiTheme.FONT_SMALL);
        lblPlainTitle.setForeground(UiTheme.ACCENT_CYAN);
        txtBodyText = new JTextArea();
        txtBodyText.setEditable(false);
        txtBodyText.setFont(UiTheme.FONT_MONO);
        txtBodyText.setLineWrap(true);
        pnlPlainText.add(lblPlainTitle, BorderLayout.NORTH);
        pnlPlainText.add(new JScrollPane(txtBodyText), BorderLayout.CENTER);

        JPanel pnlHtml = new JPanel(new BorderLayout(0, 4));
        pnlHtml.setOpaque(false);
        JLabel lblHtmlTitle = new JLabel("Parsed HTML Payload:");
        lblHtmlTitle.setFont(UiTheme.FONT_SMALL);
        lblHtmlTitle.setForeground(UiTheme.ACCENT_CYAN);
        txtBodyHtml = new JTextArea();
        txtBodyHtml.setEditable(false);
        txtBodyHtml.setFont(UiTheme.FONT_MONO);
        txtBodyHtml.setLineWrap(true);
        pnlHtml.add(lblHtmlTitle, BorderLayout.NORTH);
        pnlHtml.add(new JScrollPane(txtBodyHtml), BorderLayout.CENTER);

        bodyPanel.add(pnlPlainText);
        bodyPanel.add(pnlHtml);
        tabbedPane.addTab("Extracted Body Content", bodyPanel);

        resultsContainer.add(tabbedPane, BorderLayout.CENTER);

        // Bottom Action Controls
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        actionRow.setOpaque(false);

        btnCopySummary = UiTheme.createStyledButton("📋 Copy Forensic Summary", UiTheme.CARD_BG);
        btnCopySummary.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnCopySummary.setEnabled(false);
        btnCopySummary.addActionListener(e -> copyForensicSummary());

        btnSaveCase = UiTheme.createStyledButton("Save as Incident Case", UiTheme.CARD_BG);
        btnSaveCase.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnSaveCase.setEnabled(false);
        btnSaveCase.addActionListener(e -> saveAsCase());

        btnExportReport = UiTheme.createStyledButton("Export Forensic Report (HTML)", UiTheme.ACCENT_CYAN);
        btnExportReport.setEnabled(false);
        btnExportReport.addActionListener(e -> exportHtmlReport());

        actionRow.add(btnCopySummary);
        actionRow.add(btnSaveCase);
        actionRow.add(btnExportReport);
        resultsContainer.add(actionRow, BorderLayout.SOUTH);
    }

    private JPanel buildForensicSummaryCard() {
        JPanel card = UiTheme.createCardPanel();
        card.setLayout(new BorderLayout(0, 8));

        // 1. Top Verdict Bar
        JPanel topVerdict = new JPanel(new BorderLayout(8, 0));
        topVerdict.setOpaque(false);

        JPanel leftBadges = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        leftBadges.setOpaque(false);

        lblRiskBadge = UiTheme.createRiskBadge(RiskLevel.INSUFFICIENT_DATA);
        lblScoreValue = new JLabel("Score: -- / 100");
        lblScoreValue.setFont(UiTheme.FONT_HEADER);
        lblConfidenceValue = new JLabel("Confidence: --");
        lblConfidenceValue.setFont(UiTheme.FONT_SMALL);
        lblConfidenceValue.setForeground(UiTheme.TEXT_MUTED);

        leftBadges.add(lblRiskBadge);
        leftBadges.add(lblScoreValue);
        leftBadges.add(lblConfidenceValue);

        lblStatusNotice = new JLabel("● Ready for Ingestion");
        lblStatusNotice.setFont(UiTheme.FONT_SMALL);
        lblStatusNotice.setForeground(UiTheme.ACCENT_CYAN);

        topVerdict.add(leftBadges, BorderLayout.WEST);
        topVerdict.add(lblStatusNotice, BorderLayout.EAST);
        card.add(topVerdict, BorderLayout.NORTH);

        // 2. Center: Forensic Identification Box & Metadata
        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.Y_AXIS));
        centerPanel.setOpaque(false);

        // Highlight Box for Unique IDs
        JPanel idBox = new JPanel(new GridBagLayout());
        idBox.setBackground(new Color(0x13, 0x1E, 0x32));
        idBox.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x1E, 0x3A, 0x5F), 1),
                new EmptyBorder(6, 10, 6, 10)
        ));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(2, 4, 2, 8);

        // Row 0: Unique Message ID
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0;
        JLabel lblMsgIdTitle = new JLabel("Unique Message-ID:");
        lblMsgIdTitle.setFont(UiTheme.FONT_BOLD);
        lblMsgIdTitle.setForeground(UiTheme.ACCENT_CYAN);
        idBox.add(lblMsgIdTitle, gbc);

        gbc.gridx = 1; gbc.weightx = 1.0;
        lblUniqueMessageId = new JLabel("Not Analyzed");
        lblUniqueMessageId.setFont(UiTheme.FONT_MONO);
        lblUniqueMessageId.setForeground(UiTheme.TEXT_PRIMARY);
        idBox.add(lblUniqueMessageId, gbc);

        gbc.gridx = 2; gbc.weightx = 0.0;
        JButton btnCopyId = new JButton("Copy ID");
        btnCopyId.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        btnCopyId.setMargin(new Insets(1, 6, 1, 6));
        btnCopyId.addActionListener(e -> copyToClipboard(lblUniqueMessageId.getText()));
        idBox.add(btnCopyId, gbc);

        // Row 1: Forensic SHA-256 Hash
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0;
        JLabel lblHashTitle = new JLabel("Forensic SHA-256:");
        lblHashTitle.setFont(UiTheme.FONT_BOLD);
        lblHashTitle.setForeground(UiTheme.TEXT_MUTED);
        idBox.add(lblHashTitle, gbc);

        gbc.gridx = 1; gbc.weightx = 1.0;
        lblSha256 = new JLabel("--");
        lblSha256.setFont(UiTheme.FONT_MONO);
        lblSha256.setForeground(UiTheme.TEXT_MUTED);
        idBox.add(lblSha256, gbc);

        gbc.gridx = 2; gbc.weightx = 0.0;
        JButton btnCopyHash = new JButton("Copy Hash");
        btnCopyHash.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        btnCopyHash.setMargin(new Insets(1, 6, 1, 6));
        btnCopyHash.addActionListener(e -> copyToClipboard(lblSha256.getText()));
        idBox.add(btnCopyHash, gbc);

        centerPanel.add(idBox);
        centerPanel.add(Box.createVerticalStrut(6));

        // Envelope Metadata Grid (2 columns)
        JPanel metaGrid = new JPanel(new GridLayout(3, 2, 12, 3));
        metaGrid.setOpaque(false);

        lblSubject = new JLabel("Subject: --");
        lblSubject.setFont(UiTheme.FONT_REGULAR);

        lblFrom = new JLabel("From: --");
        lblFrom.setFont(UiTheme.FONT_REGULAR);

        lblTo = new JLabel("To: --");
        lblTo.setFont(UiTheme.FONT_REGULAR);

        lblSenderDomain = new JLabel("Sender Domain: --");
        lblSenderDomain.setFont(UiTheme.FONT_REGULAR);

        lblReturnPath = new JLabel("Return-Path: --");
        lblReturnPath.setFont(UiTheme.FONT_REGULAR);

        lblDate = new JLabel("Date: --");
        lblDate.setFont(UiTheme.FONT_REGULAR);

        metaGrid.add(lblSubject);
        metaGrid.add(lblFrom);
        metaGrid.add(lblTo);
        metaGrid.add(lblSenderDomain);
        metaGrid.add(lblReturnPath);
        metaGrid.add(lblDate);

        centerPanel.add(metaGrid);
        centerPanel.add(Box.createVerticalStrut(6));

        // Explanation Text Area
        txtScoreExplanation = new JTextArea("Ready to analyze. Paste email headers and body or load a scenario fixture to begin.");
        txtScoreExplanation.setWrapStyleWord(true);
        txtScoreExplanation.setLineWrap(true);
        txtScoreExplanation.setEditable(false);
        txtScoreExplanation.setFont(UiTheme.FONT_REGULAR);
        txtScoreExplanation.setBackground(UiTheme.CARD_BG);
        txtScoreExplanation.setBorder(null);
        centerPanel.add(txtScoreExplanation);

        card.add(centerPanel, BorderLayout.CENTER);

        // 3. Bottom: Authentication Status Bar
        lblAuthResults = new JLabel("Authentication: SPF: Unknown | DKIM: Unknown | DMARC: Unknown");
        lblAuthResults.setFont(UiTheme.FONT_SMALL);
        lblAuthResults.setForeground(UiTheme.ACCENT_CYAN);
        card.add(lblAuthResults, BorderLayout.SOUTH);

        return card;
    }

    private void runAnalysis() {
        String rawText = txtInputEmail.getText();
        if (rawText == null || rawText.isBlank()) {
            JOptionPane.showMessageDialog(this, "Please paste an email or load a scenario fixture first.", "Input Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        btnAnalyze.setEnabled(false);
        progressBar.setVisible(true);
        lblStatusNotice.setText("⚡ Ingesting & Analyzing Forensics...");
        lblStatusNotice.setForeground(UiTheme.COLOR_MEDIUM);

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
                    btnCopySummary.setEnabled(true);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(AnalyzeEmailPanel.this,
                            "Analysis Error: " + ex.getMessage(), "Parser / Engine Error", JOptionPane.ERROR_MESSAGE);
                    lblStatusNotice.setText("✖ Analysis Error");
                    lblStatusNotice.setForeground(UiTheme.COLOR_CRITICAL);
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

        // 1. Update Verdict Badges & Scores
        lblRiskBadge.setText(" " + risk.getRiskLevel().getLabel().toUpperCase() + " ");
        Color bg = switch (risk.getRiskLevel()) {
            case CRITICAL -> UiTheme.COLOR_CRITICAL;
            case HIGH -> UiTheme.COLOR_HIGH;
            case MEDIUM -> UiTheme.COLOR_MEDIUM;
            case LOW -> UiTheme.COLOR_LOW;
            case INSUFFICIENT_DATA -> UiTheme.COLOR_INFO;
        };
        lblRiskBadge.setBackground(bg);

        lblScoreValue.setText("Score: " + risk.getScore() + " / 100");
        lblScoreValue.setForeground(bg);

        lblConfidenceValue.setText("Confidence: " + risk.getFormattedConfidence());
        lblStatusNotice.setText("● Forensic Analysis Completed (" + res.getFindings().size() + " findings)");
        lblStatusNotice.setForeground(UiTheme.COLOR_LOW);

        // 2. Update Unique ID & Forensic Identifiers
        String uniqueId = msg.getDisplayUniqueId();
        lblUniqueMessageId.setText(uniqueId);
        lblUniqueMessageId.setToolTipText(uniqueId);

        String sha256 = msg.getRawSha256();
        lblSha256.setText(sha256);
        lblSha256.setToolTipText(sha256);

        // 3. Update Envelope Metadata Grid
        lblSubject.setText("Subject: " + (msg.getSubject().isBlank() ? "(No Subject)" : msg.getSubject()));
        lblSubject.setToolTipText(msg.getSubject());

        lblFrom.setText("From: " + (msg.getFrom().isBlank() ? (msg.getFromAddress().isBlank() ? "(Unknown)" : msg.getFromAddress()) : msg.getFrom()));
        lblFrom.setToolTipText(msg.getFrom());

        String toStr = msg.getTo().isEmpty() ? "(No To Header)" : String.join(", ", msg.getTo());
        lblTo.setText("To: " + toStr);
        lblTo.setToolTipText(toStr);

        lblSenderDomain.setText("Sender Domain: " + (msg.getSenderDomain().isBlank() ? "(Unparsed)" : msg.getSenderDomain()));
        lblReturnPath.setText("Return-Path: " + (msg.getReturnPath().isBlank() ? "(None)" : msg.getReturnPath()));
        lblDate.setText("Date: " + msg.getDate().toString());

        txtScoreExplanation.setText(risk.getExplanation());

        // 4. Update Authentication Status
        AuthenticationResult auth = msg.getAuthResult();
        String spfColor = auth.getSpfStatus() == AuthenticationResult.AuthStatus.PASS ? "Pass" :
                         auth.getSpfStatus() == AuthenticationResult.AuthStatus.FAIL ? "FAIL" : "Unknown";
        String dkimColor = auth.getDkimStatus() == AuthenticationResult.AuthStatus.PASS ? "Pass" :
                          auth.getDkimStatus() == AuthenticationResult.AuthStatus.FAIL ? "FAIL" : "Unknown";
        String dmarcColor = auth.getDmarcStatus() == AuthenticationResult.AuthStatus.PASS ? "Pass" :
                           auth.getDmarcStatus() == AuthenticationResult.AuthStatus.FAIL ? "FAIL" : "Unknown";

        lblAuthResults.setText(String.format("Authentication Verdicts: SPF: %s | DKIM: %s | DMARC: %s | Envelope Domain: %s",
                spfColor, dkimColor, dmarcColor, msg.getSenderDomain().isBlank() ? "N/A" : msg.getSenderDomain()));

        // 5. Populate Findings Table
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
        tabbedPane.setTitleAt(0, "Detection Findings & Audit (" + res.getFindings().size() + ")");

        // 6. Populate URLs Table
        urlsTableModel.setRowCount(0);
        for (ExtractedUrl u : msg.getExtractedUrls()) {
            urlsTableModel.addRow(new Object[]{
                    u.getAnchorText().isBlank() ? "(Direct Link)" : u.getAnchorText(),
                    u.getOriginalUrl(),
                    u.getDomain(),
                    u.getSuspiciousReasons().isEmpty() ? "Verified Benign" : String.join(", ", u.getSuspiciousReasons())
            });
        }
        tabbedPane.setTitleAt(1, "Extracted URLs (" + msg.getExtractedUrls().size() + ")");

        // 7. Populate All Email Headers Table
        headersTableModel.setRowCount(0);
        for (EmailHeader h : msg.getHeaders()) {
            headersTableModel.addRow(new Object[]{
                    h.getName(),
                    h.getValue()
            });
        }
        tabbedPane.setTitleAt(2, "Email Headers & Attributes (" + msg.getHeaders().size() + ")");

        // 8. Populate Attachments Table
        attachmentsTableModel.setRowCount(0);
        for (EmailAttachmentMetadata att : msg.getAttachments()) {
            attachmentsTableModel.addRow(new Object[]{
                    att.getFilename(),
                    att.getContentType(),
                    att.getFormattedSize(),
                    att.getSha256Hash(),
                    att.isSuspicious() ? att.getSuspiciousReason() : "Verified Safe"
            });
        }
        tabbedPane.setTitleAt(3, "Attachments Metadata (" + msg.getAttachments().size() + ")");

        // 9. Populate Body Views
        txtBodyText.setText(msg.getBodyText().isBlank() ? "(No Plain Text Body Parsed)" : msg.getBodyText());
        txtBodyHtml.setText(msg.getBodyHtml().isBlank() ? "(No HTML Body Parsed)" : msg.getBodyHtml());

        revalidate();
        repaint();
    }

    private void copyToClipboard(String text) {
        if (text == null || text.isBlank()) return;
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        JOptionPane.showMessageDialog(this, "Copied to clipboard:\n" + text, "Copied", JOptionPane.INFORMATION_MESSAGE);
    }

    private void copyForensicSummary() {
        if (currentMessage == null || currentResult == null) return;

        StringBuilder sb = new StringBuilder();
        sb.append("=== MAILSHIELD EMAIL FORENSIC AUDIT REPORT ===\n");
        sb.append("Unique Message-ID: ").append(currentMessage.getDisplayUniqueId()).append("\n");
        sb.append("Forensic SHA-256:  ").append(currentMessage.getRawSha256()).append("\n");
        sb.append("Subject:           ").append(currentMessage.getSubject()).append("\n");
        sb.append("From:              ").append(currentMessage.getFrom()).append("\n");
        sb.append("Sender Domain:     ").append(currentMessage.getSenderDomain()).append("\n");
        sb.append("Return-Path:       ").append(currentMessage.getReturnPath()).append("\n");
        sb.append("To:                ").append(String.join(", ", currentMessage.getTo())).append("\n");
        sb.append("Date:              ").append(currentMessage.getDate()).append("\n");
        sb.append("Risk Level:        ").append(currentResult.getRiskAssessment().getRiskLevel().getLabel()).append("\n");
        sb.append("Risk Score:        ").append(currentResult.getRiskAssessment().getScore()).append("/100\n");
        sb.append("Confidence:        ").append(currentResult.getRiskAssessment().getFormattedConfidence()).append("\n");
        sb.append("Authentication:    ").append(currentMessage.getAuthResult()).append("\n");
        sb.append("\n--- DETECTION FINDINGS & AUDIT (").append(currentResult.getFindings().size()).append(") ---\n");
        for (Finding f : currentResult.getFindings()) {
            sb.append(String.format("[%s] %s (%s): %s | Evidence: %s\n",
                    f.getSeverity(), f.getRuleId(), f.getCategory().getLabel(), f.getShortDescription(), f.getEvidenceSnippet()));
        }
        sb.append("\n--- EXTRACTED URLS (").append(currentMessage.getExtractedUrls().size()).append(") ---\n");
        for (ExtractedUrl u : currentMessage.getExtractedUrls()) {
            sb.append(String.format("• %s -> %s [%s]\n",
                    u.getDomain(), u.getOriginalUrl(), u.getSuspiciousReasons().isEmpty() ? "Benign" : String.join(", ", u.getSuspiciousReasons())));
        }

        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
        JOptionPane.showMessageDialog(this, "Forensic audit summary successfully copied to clipboard!", "Copied", JOptionPane.INFORMATION_MESSAGE);
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
