package com.mailshield.ui;

import com.mailshield.model.*;
import com.mailshield.monitoring.MonitoringService;
import com.mailshield.reporting.ReportGenerator;
import com.mailshield.storage.CaseRepository;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Screen 4: Email Investigation Queue.
 * Search, filter, paginate (100 emails/page), and inspect historically analyzed email records
 * with comprehensive SOC content inspection and forensic audits.
 */
public class InvestigationQueuePanel extends JPanel {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
            .withZone(ZoneId.systemDefault());

    private final CaseRepository caseRepository;
    private final MonitoringService monitoringService;
    private final ReportGenerator reportGenerator;

    private JTable table;
    private DefaultTableModel tableModel;
    private JComboBox<String> cmbRiskFilter;
    private JTextField txtSearch;

    private final List<EmailMessage> loadedEmails = new ArrayList<>();
    private final List<EmailMessage> filteredEmails = new ArrayList<>();
    private final List<EmailMessage> currentPageEmails = new ArrayList<>();

    // Pagination State (defaults to 100 per page)
    private int pageSize = 100;
    private int currentPage = 1;
    private int totalPages = 1;

    // Pagination Controls
    private JLabel lblPageInfo;
    private JButton btnFirst;
    private JButton btnPrev;
    private JButton btnNext;
    private JButton btnLast;
    private JComboBox<String> cmbPageSize;
    private JButton btnViewEmail;
    private JButton btnTopViewEmail;

    public InvestigationQueuePanel(CaseRepository caseRepository, MonitoringService monitoringService, ReportGenerator reportGenerator) {
        this.caseRepository = caseRepository;
        this.monitoringService = monitoringService;
        this.reportGenerator = reportGenerator;

        setLayout(new BorderLayout(16, 12));
        setBackground(UiTheme.BG_DARK);
        setBorder(new EmptyBorder(16, 20, 16, 20));

        initHeader();
        initTable();
        refreshQueue();
    }

    public InvestigationQueuePanel(CaseRepository caseRepository, MonitoringService monitoringService) {
        this(caseRepository, monitoringService, null);
    }

    public InvestigationQueuePanel(CaseRepository caseRepository) {
        this(caseRepository, null, null);
    }

    private void initHeader() {
        JPanel header = new JPanel(new BorderLayout(12, 10));
        header.setOpaque(false);

        JLabel title = new JLabel("Email Investigation & Triage Queue");
        title.setFont(UiTheme.FONT_TITLE);

        JLabel subtitle = new JLabel("Displaying 100 emails per page. Click or double-click any email row to inspect its full content & forensic indicators.");
        subtitle.setFont(UiTheme.FONT_SMALL);
        subtitle.setForeground(UiTheme.TEXT_MUTED);

        JPanel text = new JPanel(new GridLayout(2, 1, 0, 4));
        text.setOpaque(false);
        text.add(title);
        text.add(subtitle);

        // Filter & Search Controls Bar
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        filterBar.setOpaque(false);

        JLabel lblFilter = new JLabel("Risk Filter:");
        lblFilter.setFont(UiTheme.FONT_SMALL);
        lblFilter.setForeground(UiTheme.TEXT_MUTED);

        cmbRiskFilter = new JComboBox<>(new String[]{"All Risk Levels", "CRITICAL", "HIGH", "MEDIUM", "LOW"});
        cmbRiskFilter.addActionListener(e -> applyFilter());

        txtSearch = new JTextField(14);
        txtSearch.putClientProperty("JTextField.placeholderText", "Search subject or sender...");
        txtSearch.addActionListener(e -> applyFilter());

        JButton btnSearch = UiTheme.createStyledButton("Search", UiTheme.CARD_BG);
        btnSearch.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnSearch.addActionListener(e -> applyFilter());

        btnTopViewEmail = UiTheme.createStyledButton("👁 View Email Content", UiTheme.ACCENT_CYAN);
        btnTopViewEmail.setForeground(Color.BLACK);
        btnTopViewEmail.setEnabled(false);
        btnTopViewEmail.setToolTipText("Open the selected email to inspect body, headers, links, and threat findings");
        btnTopViewEmail.addActionListener(e -> openSelectedEmailDetails());

        JButton btnRefreshAll = UiTheme.createStyledButton("↻ Refresh Emails", UiTheme.ACCENT_BLUE);
        btnRefreshAll.setToolTipText("Fetch and refresh all emails from connected inboxes (Gmail/Outlook) and database");
        btnRefreshAll.addActionListener(e -> performFullRefresh(btnRefreshAll));

        filterBar.add(lblFilter);
        filterBar.add(cmbRiskFilter);
        filterBar.add(txtSearch);
        filterBar.add(btnSearch);
        filterBar.add(btnTopViewEmail);
        filterBar.add(btnRefreshAll);

        header.add(text, BorderLayout.WEST);
        header.add(filterBar, BorderLayout.EAST);
        add(header, BorderLayout.NORTH);
    }

    private void initTable() {
        String[] cols = {"Ingestion Timestamp", "Source Provider", "Sender (From)", "Subject", "Risk Level", "Score", "Original SHA-256 Digest"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        table = new JTable(tableModel);
        table.setRowHeight(28);
        table.setFont(UiTheme.FONT_REGULAR);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getColumnModel().getColumn(0).setPreferredWidth(120);
        table.getColumnModel().getColumn(1).setPreferredWidth(110);
        table.getColumnModel().getColumn(2).setPreferredWidth(160);
        table.getColumnModel().getColumn(3).setPreferredWidth(230);
        table.getColumnModel().getColumn(4).setPreferredWidth(90);
        table.getColumnModel().getColumn(5).setPreferredWidth(50);
        table.getColumnModel().getColumn(6).setPreferredWidth(200);

        // Click to view email content
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int row = table.getSelectedRow();
                boolean selected = (row != -1);
                if (btnViewEmail != null) btnViewEmail.setEnabled(selected);
                if (btnTopViewEmail != null) btnTopViewEmail.setEnabled(selected);

                // On double click, immediately open email content dialog
                if (e.getClickCount() >= 2 && selected) {
                    openSelectedEmailDetails();
                }
            }
        });

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                boolean selected = (table.getSelectedRow() != -1);
                if (btnViewEmail != null) btnViewEmail.setEnabled(selected);
                if (btnTopViewEmail != null) btnTopViewEmail.setEnabled(selected);
            }
        });

        table.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if ((e.getKeyCode() == KeyEvent.VK_ENTER || e.getKeyCode() == KeyEvent.VK_SPACE) && table.getSelectedRow() != -1) {
                    e.consume();
                    openSelectedEmailDetails();
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));

        JPanel centerPanel = new JPanel(new BorderLayout(0, 8));
        centerPanel.setOpaque(false);
        centerPanel.add(scrollPane, BorderLayout.CENTER);
        centerPanel.add(initPaginationBar(), BorderLayout.SOUTH);

        add(centerPanel, BorderLayout.CENTER);
    }

    private JPanel initPaginationBar() {
        JPanel bar = new JPanel(new BorderLayout(12, 0));
        bar.setBackground(UiTheme.CARD_BG);
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1),
                new EmptyBorder(6, 14, 6, 14)
        ));

        // Left: Page items info
        lblPageInfo = new JLabel("Showing 0–0 of 0 emails  |  Page 1 of 1");
        lblPageInfo.setFont(UiTheme.FONT_SMALL);
        lblPageInfo.setForeground(UiTheme.TEXT_MUTED);

        // Center: Navigation buttons
        JPanel navPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 6, 0));
        navPanel.setOpaque(false);

        btnFirst = UiTheme.createStyledButton("⏮ First", UiTheme.BG_DARK);
        btnFirst.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnFirst.setFont(UiTheme.FONT_SMALL);
        btnFirst.addActionListener(e -> goToPage(1));

        btnPrev = UiTheme.createStyledButton("◀ Previous", UiTheme.BG_DARK);
        btnPrev.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnPrev.setFont(UiTheme.FONT_SMALL);
        btnPrev.addActionListener(e -> goToPage(currentPage - 1));

        btnNext = UiTheme.createStyledButton("Next ▶", UiTheme.BG_DARK);
        btnNext.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnNext.setFont(UiTheme.FONT_SMALL);
        btnNext.addActionListener(e -> goToPage(currentPage + 1));

        btnLast = UiTheme.createStyledButton("Last ⏭", UiTheme.BG_DARK);
        btnLast.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnLast.setFont(UiTheme.FONT_SMALL);
        btnLast.addActionListener(e -> goToPage(totalPages));

        navPanel.add(btnFirst);
        navPanel.add(btnPrev);
        navPanel.add(btnNext);
        navPanel.add(btnLast);

        // Right: Page size selector + View Email Content action button
        JPanel rightControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        rightControls.setOpaque(false);

        JLabel lblSize = new JLabel("Per Page:");
        lblSize.setFont(UiTheme.FONT_SMALL);
        lblSize.setForeground(UiTheme.TEXT_MUTED);

        cmbPageSize = new JComboBox<>(new String[]{"100 emails", "200 emails", "500 emails"});
        cmbPageSize.setFont(UiTheme.FONT_SMALL);
        cmbPageSize.addActionListener(e -> {
            String sel = (String) cmbPageSize.getSelectedItem();
            if (sel != null) {
                if (sel.startsWith("100")) pageSize = 100;
                else if (sel.startsWith("200")) pageSize = 200;
                else if (sel.startsWith("500")) pageSize = 500;
                currentPage = 1;
                renderCurrentPage();
            }
        });

        btnViewEmail = UiTheme.createStyledButton("👁 View Email Content", UiTheme.ACCENT_CYAN);
        btnViewEmail.setForeground(Color.BLACK);
        btnViewEmail.setFont(UiTheme.FONT_BOLD);
        btnViewEmail.setEnabled(false);
        btnViewEmail.setToolTipText("Open the selected email to inspect content, headers, links, and threat findings");
        btnViewEmail.addActionListener(e -> openSelectedEmailDetails());

        rightControls.add(lblSize);
        rightControls.add(cmbPageSize);
        rightControls.add(btnViewEmail);

        bar.add(lblPageInfo, BorderLayout.WEST);
        bar.add(navPanel, BorderLayout.CENTER);
        bar.add(rightControls, BorderLayout.EAST);

        return bar;
    }

    private void goToPage(int page) {
        if (page < 1) page = 1;
        if (page > totalPages) page = totalPages;
        this.currentPage = page;
        renderCurrentPage();
    }

    public void openSelectedEmailDetails() {
        int selectedRow = table.getSelectedRow();
        if (selectedRow == -1 || selectedRow >= currentPageEmails.size()) {
            JOptionPane.showMessageDialog(this,
                    "Please click on an email row from the table first.",
                    "No Email Selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        EmailMessage selectedEmail = currentPageEmails.get(selectedRow);
        AnalysisResult analysis = null;
        if (caseRepository != null) {
            analysis = caseRepository.findAnalysisResultByEmailId(selectedEmail.getId()).orElse(null);
        }

        EmailDetailsDialog dialog = new EmailDetailsDialog(
                SwingUtilities.getWindowAncestor(this),
                selectedEmail,
                analysis,
                caseRepository,
                reportGenerator
        );
        dialog.setVisible(true);
    }

    public void performFullRefresh(JButton sourceButton) {
        if (sourceButton != null) {
            sourceButton.setEnabled(false);
            sourceButton.setText("↻ Refreshing...");
        }

        SwingWorker<Integer, Void> worker = new SwingWorker<>() {
            @Override
            protected Integer doInBackground() {
                int newSynced = 0;
                if (monitoringService != null && monitoringService.hasAnyConnectedProvider()) {
                    newSynced = monitoringService.triggerSyncAllConnected(25);
                }
                return newSynced;
            }

            @Override
            protected void done() {
                try {
                    int newCount = get();
                    refreshQueue();

                    int totalLoaded = loadedEmails.size();
                    if (newCount > 0) {
                        JOptionPane.showMessageDialog(InvestigationQueuePanel.this,
                                "✓ Inboxes Refreshed Successfully!\n\n" +
                                "Ingested and analyzed: " + newCount + " new email(s).\n" +
                                "Total emails in queue: " + totalLoaded + ".\n\n" +
                                "All risk indicators, URL forensics, and evidence custody records have been updated.",
                                "Email Refresh Complete", JOptionPane.INFORMATION_MESSAGE);
                    } else if (monitoringService != null && monitoringService.hasAnyConnectedProvider()) {
                        JOptionPane.showMessageDialog(InvestigationQueuePanel.this,
                                "✓ All Inboxes Up-to-Date\n\n" +
                                "Connected mailboxes were synchronized. No new incoming messages found.\n" +
                                "Total emails in triage queue: " + totalLoaded + ".",
                                "Queue Refreshed", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(InvestigationQueuePanel.this,
                                "✓ Email Queue Refreshed\n\n" +
                                "Loaded " + totalLoaded + " email record(s) from local forensic database.\n\n" +
                                "ℹ To synchronize live emails directly from Google Gmail or Microsoft 365,\n" +
                                "please visit 'Connected Inboxes' (Screen 3) to authorize your account.",
                                "Local Queue Refreshed", JOptionPane.INFORMATION_MESSAGE);
                    }
                } catch (Exception ex) {
                    refreshQueue();
                    JOptionPane.showMessageDialog(InvestigationQueuePanel.this,
                            "Synchronization encountered an issue: " + ex.getMessage() + "\n\nLocal queue was reloaded.",
                            "Refresh Warning", JOptionPane.WARNING_MESSAGE);
                } finally {
                    if (sourceButton != null) {
                        sourceButton.setEnabled(true);
                        sourceButton.setText("↻ Refresh Emails");
                    }
                }
            }
        };
        worker.execute();
    }

    public void refreshQueue() {
        if (caseRepository == null) return;
        loadedEmails.clear();
        // Load up to 2500 emails to support large inboxes with multi-page browsing
        loadedEmails.addAll(caseRepository.findAllEmails(2500, 0));
        applyFilter();
    }

    private void applyFilter() {
        filteredEmails.clear();
        String selectedRisk = (String) cmbRiskFilter.getSelectedItem();
        String query = txtSearch.getText().trim().toLowerCase();

        for (EmailMessage m : loadedEmails) {
            Optional<AnalysisResult> analysisOpt = caseRepository != null ? caseRepository.findAnalysisResultByEmailId(m.getId()) : Optional.empty();
            RiskLevel level = analysisOpt.map(a -> a.getRiskAssessment().getRiskLevel()).orElse(RiskLevel.LOW);

            if (selectedRisk != null && !selectedRisk.equals("All Risk Levels") && !level.name().equalsIgnoreCase(selectedRisk)) {
                continue;
            }

            if (!query.isBlank()) {
                String sub = m.getSubject() != null ? m.getSubject().toLowerCase() : "";
                String from = m.getFromAddress() != null ? m.getFromAddress().toLowerCase() : "";
                if (!sub.contains(query) && !from.contains(query)) {
                    continue;
                }
            }

            filteredEmails.add(m);
        }

        currentPage = 1;
        renderCurrentPage();
    }

    private void renderCurrentPage() {
        tableModel.setRowCount(0);
        currentPageEmails.clear();

        int totalCount = filteredEmails.size();
        totalPages = Math.max(1, (int) Math.ceil((double) totalCount / pageSize));
        if (currentPage > totalPages) currentPage = totalPages;
        if (currentPage < 1) currentPage = 1;

        int startIndex = (currentPage - 1) * pageSize;
        int endIndex = Math.min(startIndex + pageSize, totalCount);

        if (totalCount > 0 && startIndex < totalCount) {
            currentPageEmails.addAll(filteredEmails.subList(startIndex, endIndex));
        }

        for (EmailMessage m : currentPageEmails) {
            Optional<AnalysisResult> analysisOpt = caseRepository != null ? caseRepository.findAnalysisResultByEmailId(m.getId()) : Optional.empty();
            RiskLevel level = analysisOpt.map(a -> a.getRiskAssessment().getRiskLevel()).orElse(RiskLevel.LOW);
            int score = analysisOpt.map(a -> a.getRiskAssessment().getScore()).orElse(0);

            tableModel.addRow(new Object[]{
                    m.getIngestedAt() != null ? TIME_FMT.format(m.getIngestedAt()) : "-",
                    m.getProviderSource() != null ? m.getProviderSource().getTitle() : "-",
                    m.getFromAddress(),
                    m.getSubject(),
                    level.getLabel(),
                    score + "/100",
                    m.getRawSha256()
            });
        }

        // Update pagination labels and button states
        int displayStart = totalCount > 0 ? startIndex + 1 : 0;
        int displayEnd = endIndex;
        if (lblPageInfo != null) {
            lblPageInfo.setText(String.format("Showing %d–%d of %d emails  |  Page %d of %d",
                    displayStart, displayEnd, totalCount, currentPage, totalPages));
        }

        if (btnFirst != null) btnFirst.setEnabled(currentPage > 1);
        if (btnPrev != null) btnPrev.setEnabled(currentPage > 1);
        if (btnNext != null) btnNext.setEnabled(currentPage < totalPages);
        if (btnLast != null) btnLast.setEnabled(currentPage < totalPages);

        if (btnViewEmail != null) btnViewEmail.setEnabled(false);
        if (btnTopViewEmail != null) btnTopViewEmail.setEnabled(false);
    }
}
