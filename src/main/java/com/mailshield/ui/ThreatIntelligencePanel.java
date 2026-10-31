package com.mailshield.ui;

import com.mailshield.intelligence.ThreatIntelligenceService;
import com.mailshield.model.Finding;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;

/**
 * Screen 7: Threat Intelligence & IOC Reputation Feeds.
 * Displays local cyber threat feeds, IOC search bar, and reputation feeds status.
 */
public class ThreatIntelligencePanel extends JPanel {

    private final ThreatIntelligenceService threatIntelService;
    private JTextField txtIocSearch;
    private JTextArea txtIocVerdict;
    private DefaultTableModel iocTableModel;

    public ThreatIntelligencePanel(ThreatIntelligenceService threatIntelService) {
        this.threatIntelService = threatIntelService;

        setLayout(new BorderLayout(16, 16));
        setBackground(UiTheme.BG_DARK);
        setBorder(new EmptyBorder(16, 20, 16, 20));

        initHeader();
        initContent();
    }

    private void initHeader() {
        JPanel header = new JPanel(new GridLayout(2, 1, 0, 4));
        header.setOpaque(false);

        JLabel title = new JLabel("Cyber Threat Intelligence & Reputation Feeds");
        title.setFont(UiTheme.FONT_TITLE);

        JLabel subtitle = new JLabel("Correlate observed indicators of compromise (IOCs) against reputation databases and threat feeds");
        subtitle.setFont(UiTheme.FONT_SMALL);
        subtitle.setForeground(UiTheme.TEXT_MUTED);

        header.add(title);
        header.add(subtitle);
        add(header, BorderLayout.NORTH);
    }

    private void initContent() {
        JPanel center = new JPanel(new BorderLayout(0, 16));
        center.setOpaque(false);

        // Feed Status Card
        JPanel statusCard = UiTheme.createCardPanel();
        statusCard.setLayout(new GridLayout(2, 2, 16, 8));

        JLabel lblFeedName = new JLabel("Active Provider: " + (threatIntelService != null ? threatIntelService.getProviderName() : "None"));
        lblFeedName.setFont(UiTheme.FONT_BOLD);
        lblFeedName.setForeground(UiTheme.ACCENT_CYAN);

        JLabel lblMode = new JLabel("Operating Mode: " + (threatIntelService != null && threatIntelService.isOfflineFixture() ?
                "Local Curated Fixture (Deterministic Offline Viva)" : "Live Commercial API"));
        lblMode.setFont(UiTheme.FONT_REGULAR);
        lblMode.setForeground(UiTheme.TEXT_MUTED);

        JLabel lblPrivacy = new JLabel("Data Privacy: ZERO private email bodies or tokens transmitted");
        lblPrivacy.setFont(UiTheme.FONT_SMALL);
        lblPrivacy.setForeground(UiTheme.COLOR_LOW);

        JLabel lblCoverage = new JLabel("IOC Telemetry: Domain, Host IP, SHA-256 Hash, URL Pattern");
        lblCoverage.setFont(UiTheme.FONT_SMALL);
        lblCoverage.setForeground(UiTheme.TEXT_MUTED);

        statusCard.add(lblFeedName);
        statusCard.add(lblMode);
        statusCard.add(lblPrivacy);
        statusCard.add(lblCoverage);
        center.add(statusCard, BorderLayout.NORTH);

        // Search Bar & Output Split
        JPanel midPanel = new JPanel(new BorderLayout(16, 0));
        midPanel.setOpaque(false);

        // Left: Interactive Query
        JPanel queryCard = UiTheme.createCardPanel();
        queryCard.setPreferredSize(new Dimension(420, 0));
        queryCard.setLayout(new BorderLayout(0, 10));

        JLabel qTitle = new JLabel("Live Indicator Lookup (IOC)");
        qTitle.setFont(UiTheme.FONT_HEADER);
        queryCard.add(qTitle, BorderLayout.NORTH);

        JPanel inputPanel = new JPanel(new BorderLayout(8, 0));
        inputPanel.setOpaque(false);
        txtIocSearch = new JTextField();
        txtIocSearch.setFont(UiTheme.FONT_MONO);
        txtIocSearch.putClientProperty("JTextField.placeholderText", "Domain, IP (e.g. 198.51.100.55), or SHA-256...");
        txtIocSearch.addActionListener(e -> runLookup());

        JButton btnQuery = UiTheme.createStyledButton("Lookup IOC", UiTheme.ACCENT_BLUE);
        btnQuery.addActionListener(e -> runLookup());

        inputPanel.add(txtIocSearch, BorderLayout.CENTER);
        inputPanel.add(btnQuery, BorderLayout.EAST);

        txtIocVerdict = new JTextArea("Enter a domain, IP address, or attachment hash above to query threat reputation.");
        txtIocVerdict.setFont(UiTheme.FONT_MONO);
        txtIocVerdict.setEditable(false);
        txtIocVerdict.setBackground(UiTheme.CARD_BG);
        txtIocVerdict.setLineWrap(true);
        txtIocVerdict.setWrapStyleWord(true);
        JScrollPane vScroll = new JScrollPane(txtIocVerdict);
        vScroll.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));

        JPanel qCenter = new JPanel(new BorderLayout(0, 8));
        qCenter.setOpaque(false);
        qCenter.add(inputPanel, BorderLayout.NORTH);
        qCenter.add(vScroll, BorderLayout.CENTER);
        queryCard.add(qCenter, BorderLayout.CENTER);

        // Right: Active IOC Indicators & Query History
        JPanel tableCard = UiTheme.createCardPanel();
        tableCard.setLayout(new BorderLayout(0, 10));

        JLabel tblTitle = new JLabel("Indicator Lookup Telemetry & Reputation Log");
        tblTitle.setFont(UiTheme.FONT_HEADER);
        tableCard.add(tblTitle, BorderLayout.NORTH);

        String[] cols = {"Observed Indicator", "Type", "Reputation Status", "Source"};
        iocTableModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(iocTableModel);
        table.setRowHeight(28);
        table.setFont(UiTheme.FONT_REGULAR);
        JScrollPane scrollTable = new JScrollPane(table);
        scrollTable.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        tableCard.add(scrollTable, BorderLayout.CENTER);

        midPanel.add(queryCard, BorderLayout.WEST);
        midPanel.add(tableCard, BorderLayout.CENTER);

        center.add(midPanel, BorderLayout.CENTER);
        add(center, BorderLayout.CENTER);
    }

    private void runLookup() {
        String query = txtIocSearch.getText().trim();
        if (query.isBlank()) {
            JOptionPane.showMessageDialog(this, "Please enter an IOC to query.", "Input Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (threatIntelService == null) {
            txtIocVerdict.setText("Threat intelligence service is unavailable.");
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("IOC LOOKUP RESULTS FOR: ").append(query).append("\n");
        sb.append("Provider: ").append(threatIntelService.getProviderName()).append("\n\n");

        List<Finding> domainHits = threatIntelService.checkDomainReputation(query);
        List<Finding> urlHits = threatIntelService.checkUrlReputation(query);
        List<Finding> hashHits = threatIntelService.checkHashReputation(query, query);

        String type = query.contains("@") ? "Email Address" :
                      query.matches("^[a-fA-F0-9]{64}$") ? "SHA-256 Hash" :
                      query.matches("^\\d{1,3}(\\.\\d{1,3}){3}$") ? "IPv4 Host" : "Domain/URL";

        if (domainHits.isEmpty() && urlHits.isEmpty() && hashHits.isEmpty()) {
            sb.append("STATUS: CLEAN / UNKNOWN\n");
            sb.append("• No malicious activity or threat actor campaigns associated with this indicator in the active feed.\n");
            sb.append("• Note: Absence of reputation match does not guarantee absolute safety for newly registered domains.");
            if (iocTableModel != null) {
                iocTableModel.insertRow(0, new Object[]{query, type, "CLEAN / UNKNOWN", threatIntelService.getProviderName()});
            }
        } else {
            sb.append("STATUS: THREAT DETECTED (MATCH IN REPUTATION FEED)\n\n");
            for (Finding f : domainHits) {
                sb.append(String.format("• [%s] %s\n  %s\n\n", f.getSeverity().name(), f.getShortDescription(), f.getExplanation()));
            }
            for (Finding f : urlHits) {
                sb.append(String.format("• [%s] %s\n  %s\n\n", f.getSeverity().name(), f.getShortDescription(), f.getExplanation()));
            }
            for (Finding f : hashHits) {
                sb.append(String.format("• [%s] %s\n  %s\n\n", f.getSeverity().name(), f.getShortDescription(), f.getExplanation()));
            }
            sb.append("RECOMMENDED ACTION: Quarantine and block indicator at network perimeter.");
            if (iocTableModel != null) {
                iocTableModel.insertRow(0, new Object[]{query, type, "MALICIOUS / THREAT", threatIntelService.getProviderName()});
            }
        }

        txtIocVerdict.setText(sb.toString());
    }
}

