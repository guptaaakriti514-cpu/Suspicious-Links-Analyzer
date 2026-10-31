package com.mailshield.ui;

import com.mailshield.model.*;
import com.mailshield.storage.CaseRepository;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Screen 4: Email Investigation Queue.
 * Search, filter, and inspect historically analyzed email records with complete evidence audits.
 */
public class InvestigationQueuePanel extends JPanel {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
            .withZone(ZoneId.systemDefault());

    private final CaseRepository caseRepository;
    private DefaultTableModel tableModel;
    private JComboBox<String> cmbRiskFilter;
    private JTextField txtSearch;
    private List<EmailMessage> loadedEmails = new ArrayList<>();

    public InvestigationQueuePanel(CaseRepository caseRepository) {
        this.caseRepository = caseRepository;

        setLayout(new BorderLayout(16, 16));
        setBackground(UiTheme.BG_DARK);
        setBorder(new EmptyBorder(16, 20, 16, 20));

        initHeader();
        initTable();
        refreshQueue();
    }

    private void initHeader() {
        JPanel header = new JPanel(new BorderLayout(12, 10));
        header.setOpaque(false);

        JLabel title = new JLabel("Email Investigation & Triage Queue");
        title.setFont(UiTheme.FONT_TITLE);

        JLabel subtitle = new JLabel("Explore ingested mailboxes, apply risk filters, and review forensic indicators");
        subtitle.setFont(UiTheme.FONT_SMALL);
        subtitle.setForeground(UiTheme.TEXT_MUTED);

        JPanel text = new JPanel(new GridLayout(2, 1, 0, 4));
        text.setOpaque(false);
        text.add(title);
        text.add(subtitle);

        // Filter Controls Bar
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        filterBar.setOpaque(false);

        JLabel lblFilter = new JLabel("Risk Filter:");
        lblFilter.setFont(UiTheme.FONT_SMALL);
        lblFilter.setForeground(UiTheme.TEXT_MUTED);

        cmbRiskFilter = new JComboBox<>(new String[]{"All Risk Levels", "CRITICAL", "HIGH", "MEDIUM", "LOW"});
        cmbRiskFilter.addActionListener(e -> applyFilter());

        txtSearch = new JTextField(15);
        txtSearch.putClientProperty("JTextField.placeholderText", "Search subject or sender...");
        txtSearch.addActionListener(e -> applyFilter());

        JButton btnSearch = UiTheme.createStyledButton("Search", UiTheme.CARD_BG);
        btnSearch.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnSearch.addActionListener(e -> applyFilter());

        JButton btnReload = UiTheme.createStyledButton("↻ Reload Queue", UiTheme.CARD_BG);
        btnReload.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnReload.addActionListener(e -> refreshQueue());

        filterBar.add(lblFilter);
        filterBar.add(cmbRiskFilter);
        filterBar.add(txtSearch);
        filterBar.add(btnSearch);
        filterBar.add(btnReload);

        header.add(text, BorderLayout.WEST);
        header.add(filterBar, BorderLayout.EAST);
        add(header, BorderLayout.NORTH);
    }

    private void initTable() {
        String[] cols = {"Ingestion Timestamp", "Source Provider", "Sender (From)", "Subject", "Risk Level", "Score", "Original SHA-256 Digest"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(tableModel);
        table.setRowHeight(28);
        table.setFont(UiTheme.FONT_REGULAR);
        table.getColumnModel().getColumn(0).setPreferredWidth(120);
        table.getColumnModel().getColumn(1).setPreferredWidth(110);
        table.getColumnModel().getColumn(2).setPreferredWidth(160);
        table.getColumnModel().getColumn(3).setPreferredWidth(220);
        table.getColumnModel().getColumn(4).setPreferredWidth(90);
        table.getColumnModel().getColumn(5).setPreferredWidth(50);
        table.getColumnModel().getColumn(6).setPreferredWidth(200);

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        add(scrollPane, BorderLayout.CENTER);
    }

    public void refreshQueue() {
        if (caseRepository == null) return;
        loadedEmails = caseRepository.findAllEmails(100, 0);
        applyFilter();
    }

    private void applyFilter() {
        tableModel.setRowCount(0);
        String selectedRisk = (String) cmbRiskFilter.getSelectedItem();
        String query = txtSearch.getText().trim().toLowerCase();

        for (EmailMessage m : loadedEmails) {
            var analysisOpt = caseRepository.findAnalysisResultByEmailId(m.getId());
            RiskLevel level = analysisOpt.map(a -> a.getRiskAssessment().getRiskLevel()).orElse(RiskLevel.LOW);
            int score = analysisOpt.map(a -> a.getRiskAssessment().getScore()).orElse(0);

            if (selectedRisk != null && !selectedRisk.equals("All Risk Levels") && !level.name().equalsIgnoreCase(selectedRisk)) {
                continue;
            }

            if (!query.isBlank()) {
                String sub = m.getSubject().toLowerCase();
                String from = m.getFromAddress().toLowerCase();
                if (!sub.contains(query) && !from.contains(query)) {
                    continue;
                }
            }

            tableModel.addRow(new Object[]{
                    TIME_FMT.format(m.getIngestedAt()),
                    m.getProviderSource().getTitle(),
                    m.getFromAddress(),
                    m.getSubject(),
                    level.getLabel(),
                    score + "/100",
                    m.getRawSha256()
            });
        }
    }
}

