package com.mailshield.ui;

import com.mailshield.model.*;
import com.mailshield.storage.CaseRepository;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Screen 6: SOC Incident Case Management.
 * Track cases, record analyst notes, escalate confirmed threats, and correlate forensic evidence.
 */
public class CasesPanel extends JPanel {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
            .withZone(ZoneId.systemDefault());

    private final CaseRepository caseRepository;
    private DefaultTableModel casesTableModel;
    private JTextArea txtNotesArea;
    private JComboBox<CaseStatus> cmbStatusUpdate;
    private InvestigationCase selectedCase;
    private JLabel lblSelectedCaseTitle;

    public CasesPanel(CaseRepository caseRepository) {
        this.caseRepository = caseRepository;

        setLayout(new BorderLayout(16, 16));
        setBackground(UiTheme.BG_DARK);
        setBorder(new EmptyBorder(16, 20, 16, 20));

        initHeader();
        initContent();
        refreshCases();
    }

    private void initHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);

        JLabel title = new JLabel("Cybersecurity Incident Investigation Cases");
        title.setFont(UiTheme.FONT_TITLE);

        JLabel subtitle = new JLabel("Manage forensic email cases, assign priorities, record analyst notes, and maintain chain of custody");
        subtitle.setFont(UiTheme.FONT_SMALL);
        subtitle.setForeground(UiTheme.TEXT_MUTED);

        JPanel text = new JPanel(new GridLayout(2, 1, 0, 4));
        text.setOpaque(false);
        text.add(title);
        text.add(subtitle);

        JPanel btnBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        btnBar.setOpaque(false);

        JButton btnNewCase = UiTheme.createStyledButton("+ New Case", UiTheme.ACCENT_BLUE);
        btnNewCase.addActionListener(e -> createNewCaseDialog());

        JButton btnReload = UiTheme.createStyledButton("↻ Reload Cases", UiTheme.CARD_BG);
        btnReload.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnReload.addActionListener(e -> refreshCases());

        btnBar.add(btnReload);
        btnBar.add(btnNewCase);

        header.add(text, BorderLayout.WEST);
        header.add(btnBar, BorderLayout.EAST);
        add(header, BorderLayout.NORTH);
    }

    private void initContent() {
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.55);
        splitPane.setBorder(null);
        splitPane.setOpaque(false);

        // Top: Cases Table
        JPanel tableCard = UiTheme.createCardPanel();
        tableCard.setLayout(new BorderLayout(0, 10));

        String[] cols = {"Case ID", "Investigation Title", "Status", "Priority", "Assigned Analyst", "Created Date", "Associated Emails"};
        casesTableModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(casesTableModel);
        table.setRowHeight(28);
        table.setFont(UiTheme.FONT_REGULAR);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && table.getSelectedRow() >= 0) {
                String caseId = (String) table.getValueAt(table.getSelectedRow(), 0);
                loadCaseDetails(caseId);
            }
        });

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        tableCard.add(scrollPane, BorderLayout.CENTER);

        // Bottom: Case Details & Analyst Notes Editor
        JPanel detailsCard = UiTheme.createCardPanel();
        detailsCard.setLayout(new BorderLayout(0, 10));

        JPanel detailHeader = new JPanel(new BorderLayout());
        detailHeader.setOpaque(false);

        lblSelectedCaseTitle = new JLabel("Select a case above to inspect notes & update status");
        lblSelectedCaseTitle.setFont(UiTheme.FONT_HEADER);

        JPanel statusControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        statusControls.setOpaque(false);

        JLabel lblSt = new JLabel("Update Status:");
        lblSt.setFont(UiTheme.FONT_SMALL);
        lblSt.setForeground(UiTheme.TEXT_MUTED);

        cmbStatusUpdate = new JComboBox<>(CaseStatus.values());

        JButton btnSaveNotes = UiTheme.createStyledButton("Save Case Notes", UiTheme.ACCENT_CYAN);
        btnSaveNotes.addActionListener(e -> saveNotes());

        statusControls.add(lblSt);
        statusControls.add(cmbStatusUpdate);
        statusControls.add(btnSaveNotes);

        detailHeader.add(lblSelectedCaseTitle, BorderLayout.WEST);
        detailHeader.add(statusControls, BorderLayout.EAST);
        detailsCard.add(detailHeader, BorderLayout.NORTH);

        txtNotesArea = new JTextArea();
        txtNotesArea.setFont(UiTheme.FONT_REGULAR);
        txtNotesArea.setLineWrap(true);
        txtNotesArea.setWrapStyleWord(true);
        JScrollPane notesScroll = new JScrollPane(txtNotesArea);
        notesScroll.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        detailsCard.add(notesScroll, BorderLayout.CENTER);

        splitPane.setTopComponent(tableCard);
        splitPane.setBottomComponent(detailsCard);
        add(splitPane, BorderLayout.CENTER);
    }

    private void loadCaseDetails(String caseId) {
        if (caseRepository == null) return;
        var caseOpt = caseRepository.findCaseById(caseId);
        if (caseOpt.isPresent()) {
            selectedCase = caseOpt.get();
            lblSelectedCaseTitle.setText(selectedCase.getCaseId() + " — " + selectedCase.getTitle());
            txtNotesArea.setText(selectedCase.getAnalystNotes());
            cmbStatusUpdate.setSelectedItem(selectedCase.getStatus());
        }
    }

    private void saveNotes() {
        if (selectedCase == null || caseRepository == null) {
            JOptionPane.showMessageDialog(this, "No case selected.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        CaseStatus newStatus = (CaseStatus) cmbStatusUpdate.getSelectedItem();
        String newNotes = txtNotesArea.getText().trim();

        caseRepository.updateCaseNotes(selectedCase.getCaseId(), newNotes, newStatus != null ? newStatus.name() : selectedCase.getStatus().name());
        JOptionPane.showMessageDialog(this, "Case notes and status updated successfully.", "Case Updated", JOptionPane.INFORMATION_MESSAGE);
        refreshCases();
    }

    private void createNewCaseDialog() {
        JTextField txtTitle = new JTextField("Phishing Investigation");
        JComboBox<CasePriority> cmbPriority = new JComboBox<>(CasePriority.values());
        cmbPriority.setSelectedItem(CasePriority.HIGH);

        Object[] message = {
                "Investigation Title:", txtTitle,
                "Case Priority:", cmbPriority
        };

        int option = JOptionPane.showConfirmDialog(this, message, "Create New Incident Case", JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.OK_OPTION && !txtTitle.getText().isBlank()) {
            String caseId = "CASE-" + System.currentTimeMillis();
            InvestigationCase c = InvestigationCase.builder()
                    .caseId(caseId)
                    .title(txtTitle.getText().trim())
                    .status(CaseStatus.OPEN)
                    .priority((CasePriority) cmbPriority.getSelectedItem())
                    .createdAt(Instant.now())
                    .assignedAnalyst("SOC Analyst")
                    .analystNotes("Case opened manually by analyst.")
                    .build();

            if (caseRepository != null) {
                caseRepository.saveCase(c);
            }
            refreshCases();
        }
    }

    public void refreshCases() {
        if (caseRepository == null) return;
        casesTableModel.setRowCount(0);
        List<InvestigationCase> cases = caseRepository.findAllCases(50, 0);
        for (InvestigationCase c : cases) {
            casesTableModel.addRow(new Object[]{
                    c.getCaseId(),
                    c.getTitle(),
                    c.getStatus().getDisplay(),
                    c.getPriority().getLabel(),
                    c.getAssignedAnalyst(),
                    TIME_FMT.format(c.getCreatedAt()),
                    c.getAssociatedMessageIds().size()
            });
        }
    }
}

