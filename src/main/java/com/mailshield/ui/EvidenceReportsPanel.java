package com.mailshield.ui;

import com.mailshield.model.AnalysisResult;
import com.mailshield.model.EvidenceRecord;
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
import java.util.List;

/**
 * Screen 8: Forensics Evidence Custody Trail & Report Generation.
 * Manages SHA-256 cryptographic digests, chain-of-custody metadata, and report exports.
 */
public class EvidenceReportsPanel extends JPanel {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    private final CaseRepository caseRepository;
    private final ReportGenerator reportGenerator;
    private DefaultTableModel evidenceTableModel;

    public EvidenceReportsPanel(CaseRepository caseRepository, ReportGenerator reportGenerator) {
        this.caseRepository = caseRepository;
        this.reportGenerator = reportGenerator;

        setLayout(new BorderLayout(16, 16));
        setBackground(UiTheme.BG_DARK);
        setBorder(new EmptyBorder(16, 20, 16, 20));

        initHeader();
        initContent();
        refreshEvidence();
    }

    private void initHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);

        JLabel title = new JLabel("Digital Forensics Evidence & Custody Records");
        title.setFont(UiTheme.FONT_TITLE);

        JLabel subtitle = new JLabel("Immutable cryptographic audit trails, SHA-256 digests, and executive report export center");
        subtitle.setFont(UiTheme.FONT_SMALL);
        subtitle.setForeground(UiTheme.TEXT_MUTED);

        JPanel text = new JPanel(new GridLayout(2, 1, 0, 4));
        text.setOpaque(false);
        text.add(title);
        text.add(subtitle);

        JPanel btnBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        btnBar.setOpaque(false);

        JButton btnExportCsv = UiTheme.createStyledButton("Export CSV Telemetry", UiTheme.CARD_BG);
        btnExportCsv.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnExportCsv.addActionListener(e -> exportCsv());

        JButton btnReload = UiTheme.createStyledButton("↻ Reload Evidence", UiTheme.CARD_BG);
        btnReload.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnReload.addActionListener(e -> refreshEvidence());

        btnBar.add(btnExportCsv);
        btnBar.add(btnReload);

        header.add(text, BorderLayout.WEST);
        header.add(btnBar, BorderLayout.EAST);
        add(header, BorderLayout.NORTH);
    }

    private void initContent() {
        JPanel center = new JPanel(new BorderLayout(0, 16));
        center.setOpaque(false);

        // Integrity Statement Card
        JPanel infoCard = UiTheme.createCardPanel();
        infoCard.setLayout(new GridLayout(2, 1, 0, 4));

        JLabel lblTitle = new JLabel("Forensic Hash Scope & Chain of Custody Integrity");
        lblTitle.setFont(UiTheme.FONT_HEADER);
        lblTitle.setForeground(UiTheme.ACCENT_CYAN);

        JLabel lblDesc = new JLabel("<html>Hashes represent strict SHA-256 message digests computed over unaltered raw RFC 5322 byte arrays immediately upon ingestion. " +
                "Integrity is maintained locally in the SQLite audit repository. Local file access controls should be protected via OS security boundaries.</html>");
        lblDesc.setFont(UiTheme.FONT_SMALL);
        lblDesc.setForeground(UiTheme.TEXT_MUTED);

        infoCard.add(lblTitle);
        infoCard.add(lblDesc);
        center.add(infoCard, BorderLayout.NORTH);

        // Evidence Table Card
        JPanel tableCard = UiTheme.createCardPanel();
        tableCard.setLayout(new BorderLayout(0, 10));

        JLabel tblTitle = new JLabel("Custodial Evidence Records");
        tblTitle.setFont(UiTheme.FONT_HEADER);
        tableCard.add(tblTitle, BorderLayout.NORTH);

        String[] cols = {"Evidence ID", "Case ID", "Scope / Type", "Original SHA-256 Digest", "Byte Size", "Recorded Timestamp", "Origin"};
        evidenceTableModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(evidenceTableModel);
        table.setRowHeight(28);
        table.setFont(UiTheme.FONT_REGULAR);
        table.getColumnModel().getColumn(0).setPreferredWidth(100);
        table.getColumnModel().getColumn(1).setPreferredWidth(110);
        table.getColumnModel().getColumn(2).setPreferredWidth(140);
        table.getColumnModel().getColumn(3).setPreferredWidth(260);
        table.getColumnModel().getColumn(4).setPreferredWidth(70);
        table.getColumnModel().getColumn(5).setPreferredWidth(130);
        table.getColumnModel().getColumn(6).setPreferredWidth(130);

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        tableCard.add(scrollPane, BorderLayout.CENTER);

        // Table Bottom Actions
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        bottomBar.setOpaque(false);

        JButton btnCopyHash = UiTheme.createStyledButton("Copy Selected Hash", UiTheme.CARD_BG);
        btnCopyHash.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnCopyHash.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row >= 0) {
                String hash = (String) table.getValueAt(row, 3);
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(hash), null);
                JOptionPane.showMessageDialog(this, "SHA-256 digest copied to clipboard:\n" + hash, "Hash Copied", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "Please select an evidence record from the table first.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            }
        });

        bottomBar.add(btnCopyHash);
        tableCard.add(bottomBar, BorderLayout.SOUTH);

        center.add(tableCard, BorderLayout.CENTER);
        add(center, BorderLayout.CENTER);
    }

    private void exportCsv() {
        if (caseRepository == null || reportGenerator == null) return;

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("MailShield_Telemetry_Export.csv"));
        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            File target = chooser.getSelectedFile();
            try {
                List<AnalysisResult> recent = caseRepository.findRecentAnalyses(500);
                reportGenerator.generateCsvSummary(recent, target);
                JOptionPane.showMessageDialog(this, "CSV Telemetry exported successfully to:\n" + target.getAbsolutePath(),
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "CSV Export error: " + e.getMessage(), "Export Failed", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public void refreshEvidence() {
        if (caseRepository == null) return;
        evidenceTableModel.setRowCount(0);
        // Find evidence records for all cases or ad-hoc
        List<EvidenceRecord> list = caseRepository.findEvidenceByCaseId("");
        for (EvidenceRecord ev : list) {
            evidenceTableModel.addRow(new Object[]{
                    ev.getEvidenceId(),
                    ev.getCaseId().isBlank() ? "Ad-Hoc" : ev.getCaseId(),
                    ev.getEvidenceType(),
                    ev.getRawMessageSha256(),
                    ev.getOriginalByteSize() + " B",
                    TIME_FMT.format(ev.getRecordedAt()),
                    ev.getSourceDescription()
            });
        }
    }
}

