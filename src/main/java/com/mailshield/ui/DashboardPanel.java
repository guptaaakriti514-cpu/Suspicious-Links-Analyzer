package com.mailshield.ui;

import com.mailshield.model.*;
import com.mailshield.providers.EmailProvider;
import com.mailshield.storage.CaseRepository;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * Screen 1: Executive SOC Overview Dashboard.
 * Visualizes genuine persisted statistics, recent threat alerts, category breakdown,
 * and live inbox connection cards.
 */
public class DashboardPanel extends JPanel {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
            .withZone(ZoneId.systemDefault());

    private final CaseRepository caseRepository;
    private final Map<ProviderType, EmailProvider> providers;
    private final Runnable navigateToAnalyzeAction;

    private JLabel lblTotalEmails;
    private JLabel lblHighRisk;
    private JLabel lblCritical;
    private JLabel lblOpenCases;
    private JLabel lblGmailStatus;
    private JLabel lblOutlookStatus;
    private DefaultTableModel recentTableModel;

    public DashboardPanel(CaseRepository caseRepository, Map<ProviderType, EmailProvider> providers, Runnable navigateToAnalyze) {
        this.caseRepository = caseRepository;
        this.providers = providers;
        this.navigateToAnalyzeAction = navigateToAnalyze;

        setLayout(new BorderLayout(16, 16));
        setBackground(UiTheme.BG_DARK);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initHeader();
        initContent();
        refreshData();
    }

    private void initHeader() {
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setOpaque(false);

        JLabel title = new JLabel("SOC Security Operations & Threat Overview");
        title.setFont(UiTheme.FONT_TITLE);
        title.setForeground(UiTheme.TEXT_PRIMARY);

        JLabel subtitle = new JLabel("Real-time telemetry, email forensics metrics, and synchronized mailbox states");
        subtitle.setFont(UiTheme.FONT_SMALL);
        subtitle.setForeground(UiTheme.TEXT_MUTED);

        JPanel textPanel = new JPanel(new GridLayout(2, 1, 0, 4));
        textPanel.setOpaque(false);
        textPanel.add(title);
        textPanel.add(subtitle);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        btnPanel.setOpaque(false);

        JButton btnAnalyzeNow = UiTheme.createStyledButton("+ Analyze Email", UiTheme.ACCENT_BLUE);
        btnAnalyzeNow.addActionListener(e -> {
            if (navigateToAnalyzeAction != null) navigateToAnalyzeAction.run();
        });

        JButton btnRefresh = UiTheme.createStyledButton("↻ Refresh Telemetry", UiTheme.CARD_BG);
        btnRefresh.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnRefresh.addActionListener(e -> refreshData());

        btnPanel.add(btnRefresh);
        btnPanel.add(btnAnalyzeNow);

        headerPanel.add(textPanel, BorderLayout.WEST);
        headerPanel.add(btnPanel, BorderLayout.EAST);
        add(headerPanel, BorderLayout.NORTH);
    }

    private void initContent() {
        JPanel centerPanel = new JPanel(new BorderLayout(0, 20));
        centerPanel.setOpaque(false);

        // Top Row: 4 Metric Cards
        JPanel metricsRow = new JPanel(new GridLayout(1, 4, 16, 0));
        metricsRow.setOpaque(false);

        lblTotalEmails = new JLabel("0", SwingConstants.CENTER);
        lblHighRisk = new JLabel("0", SwingConstants.CENTER);
        lblCritical = new JLabel("0", SwingConstants.CENTER);
        lblOpenCases = new JLabel("0", SwingConstants.CENTER);

        metricsRow.add(createMetricCard("Total Ingested Messages", lblTotalEmails, UiTheme.TEXT_PRIMARY));
        metricsRow.add(createMetricCard("High-Risk Alerts", lblHighRisk, UiTheme.COLOR_HIGH));
        metricsRow.add(createMetricCard("Critical Threats", lblCritical, UiTheme.COLOR_CRITICAL));
        metricsRow.add(createMetricCard("Active Investigation Cases", lblOpenCases, UiTheme.ACCENT_CYAN));

        centerPanel.add(metricsRow, BorderLayout.NORTH);

        // Middle Row: Inboxes & Recent Analyses Split
        JPanel midPanel = new JPanel(new BorderLayout(16, 0));
        midPanel.setOpaque(false);

        // Recent Analyses Table Card
        JPanel tableCard = UiTheme.createCardPanel();
        tableCard.setLayout(new BorderLayout(0, 10));

        JLabel tblTitle = new JLabel("Recent Email Ingestions & Analysis Verdicts");
        tblTitle.setFont(UiTheme.FONT_HEADER);
        tableCard.add(tblTitle, BorderLayout.NORTH);

        String[] cols = {"Timestamp", "Sender Address", "Subject", "Risk Level", "Score", "Verdict Rationale"};
        recentTableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(recentTableModel);
        table.setRowHeight(28);
        table.setFont(UiTheme.FONT_REGULAR);
        table.getColumnModel().getColumn(0).setPreferredWidth(120);
        table.getColumnModel().getColumn(1).setPreferredWidth(160);
        table.getColumnModel().getColumn(2).setPreferredWidth(200);
        table.getColumnModel().getColumn(3).setPreferredWidth(90);
        table.getColumnModel().getColumn(4).setPreferredWidth(50);
        table.getColumnModel().getColumn(5).setPreferredWidth(260);

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.getViewport().setBackground(UiTheme.BG_DARK);
        scrollPane.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        tableCard.add(scrollPane, BorderLayout.CENTER);

        // Right side: Connected Inboxes Status Card
        JPanel inboxesCard = UiTheme.createCardPanel();
        inboxesCard.setPreferredSize(new Dimension(280, 0));
        inboxesCard.setLayout(new BoxLayout(inboxesCard, BoxLayout.Y_AXIS));

        JLabel inboxesTitle = new JLabel("Mailbox Connectors");
        inboxesTitle.setFont(UiTheme.FONT_HEADER);
        inboxesCard.add(inboxesTitle);
        inboxesCard.add(Box.createVerticalStrut(12));

        lblGmailStatus = new JLabel("Google Gmail API: Disconnected");
        lblGmailStatus.setFont(UiTheme.FONT_REGULAR);
        lblGmailStatus.setForeground(UiTheme.TEXT_MUTED);

        lblOutlookStatus = new JLabel("Microsoft Graph: Disconnected");
        lblOutlookStatus.setFont(UiTheme.FONT_REGULAR);
        lblOutlookStatus.setForeground(UiTheme.TEXT_MUTED);

        inboxesCard.add(createConnectorBox("Gmail API v1", lblGmailStatus, "OAuth2 PKCE (Read-Only)"));
        inboxesCard.add(Box.createVerticalStrut(12));
        inboxesCard.add(createConnectorBox("Microsoft 365", lblOutlookStatus, "Entra Delegated (Mail.Read)"));
        inboxesCard.add(Box.createVerticalStrut(16));

        // Note on sample data vs real data
        JLabel lblNotice = new JLabel("<html><small style='color:#94a3b8;'><strong>Data Integrity:</strong> Metrics are generated solely from authentic database records and verifiable sample fixtures. Live threats are never fabricated.</small></html>");
        inboxesCard.add(lblNotice);

        midPanel.add(tableCard, BorderLayout.CENTER);
        midPanel.add(inboxesCard, BorderLayout.EAST);

        centerPanel.add(midPanel, BorderLayout.CENTER);
        add(centerPanel, BorderLayout.CENTER);
    }

    private JPanel createMetricCard(String title, JLabel valueLabel, Color valueColor) {
        JPanel card = UiTheme.createCardPanel();
        card.setLayout(new GridLayout(2, 1, 0, 4));

        JLabel lblTitle = new JLabel(title);
        lblTitle.setFont(UiTheme.FONT_SMALL);
        lblTitle.setForeground(UiTheme.TEXT_MUTED);

        valueLabel.setFont(new Font("Segoe UI", Font.BOLD, 26));
        valueLabel.setForeground(valueColor);

        card.add(lblTitle);
        card.add(valueLabel);
        return card;
    }

    private JPanel createConnectorBox(String name, JLabel statusLbl, String subtext) {
        JPanel box = new JPanel(new GridLayout(3, 1, 0, 2));
        box.setBackground(UiTheme.BG_DARK);
        box.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1),
                new EmptyBorder(8, 10, 8, 10)
        ));

        JLabel nameLbl = new JLabel(name);
        nameLbl.setFont(UiTheme.FONT_BOLD);

        JLabel subLbl = new JLabel(subtext);
        subLbl.setFont(UiTheme.FONT_SMALL);
        subLbl.setForeground(UiTheme.TEXT_MUTED);

        box.add(nameLbl);
        box.add(statusLbl);
        box.add(subLbl);
        return box;
    }

    public void refreshData() {
        if (caseRepository != null) {
            lblTotalEmails.setText(String.valueOf(caseRepository.getTotalEmailCount()));
            lblHighRisk.setText(String.valueOf(caseRepository.getHighRiskEmailCount()));
            lblCritical.setText(String.valueOf(caseRepository.getCriticalEmailCount()));
            lblOpenCases.setText(String.valueOf(caseRepository.getOpenCaseCount()));

            // Update recent table
            recentTableModel.setRowCount(0);
            List<AnalysisResult> recent = caseRepository.findRecentAnalyses(15);
            for (AnalysisResult r : recent) {
                var emailOpt = caseRepository.findEmailMessageById(r.getEmailMessageId());
                String from = emailOpt.map(EmailMessage::getFromAddress).orElse("N/A");
                String subject = emailOpt.map(EmailMessage::getSubject).orElse("(No Subject)");

                recentTableModel.addRow(new Object[]{
                        TIME_FMT.format(r.getAnalyzedAt()),
                        from,
                        subject,
                        r.getRiskAssessment().getRiskLevel().getLabel(),
                        r.getRiskAssessment().getScore() + "/100",
                        r.getRiskAssessment().getExplanation()
                });
            }
        }

        // Check providers
        if (providers != null) {
            EmailProvider gmail = providers.get(ProviderType.GMAIL);
            if (gmail != null) {
                ProviderConnectionStatus st = gmail.getStatus();
                lblGmailStatus.setText(st.isConnected() ? "Connected (" + st.getAccountEmail() + ")" : st.getSyncStatus());
                lblGmailStatus.setForeground(st.isConnected() ? UiTheme.COLOR_LOW : UiTheme.TEXT_MUTED);
            }

            EmailProvider outlook = providers.get(ProviderType.OUTLOOK);
            if (outlook != null) {
                ProviderConnectionStatus st = outlook.getStatus();
                lblOutlookStatus.setText(st.isConnected() ? "Connected (" + st.getAccountEmail() + ")" : st.getSyncStatus());
                lblOutlookStatus.setForeground(st.isConnected() ? UiTheme.COLOR_LOW : UiTheme.TEXT_MUTED);
            }
        }
    }
}

