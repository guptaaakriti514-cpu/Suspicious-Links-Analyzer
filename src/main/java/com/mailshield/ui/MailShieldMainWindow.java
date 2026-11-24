package com.mailshield.ui;

import com.mailshield.app.DemoDataFixtures;
import com.mailshield.config.AppConfig;
import com.mailshield.detection.DetectionEngine;
import com.mailshield.forensics.EvidenceManager;
import com.mailshield.ingestion.EmailParser;
import com.mailshield.model.ProviderType;
import com.mailshield.monitoring.MonitoringService;
import com.mailshield.providers.EmailProvider;
import com.mailshield.reporting.ReportGenerator;
import com.mailshield.security.CredentialStore;
import com.mailshield.storage.CaseRepository;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Main Application Desktop Frame for MailShield.
 * Houses the SOC Dark Navigation Sidebar, CardLayout Content Stage, and Live Telemetry Status Bar.
 */
public class MailShieldMainWindow extends JFrame {

    private final CardLayout cardLayout = new CardLayout();
    private final JPanel contentStage = new JPanel(cardLayout);
    private final Map<String, JButton> navButtons = new LinkedHashMap<>();

    private final CaseRepository caseRepository;
    private final MonitoringService monitoringService;

    private DashboardPanel dashboardPanel;
    private AnalyzeEmailPanel analyzePanel;
    private ConnectedInboxesPanel inboxesPanel;
    private InvestigationQueuePanel queuePanel;
    private UrlDomainAnalysisPanel urlPanel;
    private CasesPanel casesPanel;
    private ThreatIntelligencePanel threatPanel;
    private EvidenceReportsPanel evidencePanel;
    private SettingsSecurityPanel settingsPanel;
    private AboutHelpPanel aboutPanel;

    private JLabel lblScreenBreadcrumb;
    private JLabel lblStatusProvider;
    private JLabel lblStatusMonitoring;

    public MailShieldMainWindow(AppConfig appConfig,
                                EmailParser emailParser,
                                DetectionEngine detectionEngine,
                                CaseRepository caseRepository,
                                EvidenceManager evidenceManager,
                                ReportGenerator reportGenerator,
                                MonitoringService monitoringService,
                                CredentialStore credentialStore,
                                Map<ProviderType, EmailProvider> providers) {

        super("MAILSHIELD — Advanced Email Threat Detection & Digital Forensics Platform v1.0.0");
        this.caseRepository = caseRepository;
        this.monitoringService = monitoringService;

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1280, 820);
        setMinimumSize(new Dimension(1024, 700));
        setLocationRelativeTo(null);

        UiTheme.setupFlatLaf();

        // Initialize 10 Screens
        this.dashboardPanel = new DashboardPanel(caseRepository, providers, monitoringService, reportGenerator, () -> switchScreen("ANALYZE"));
        this.analyzePanel = new AnalyzeEmailPanel(emailParser, detectionEngine, caseRepository, evidenceManager, reportGenerator);
        this.inboxesPanel = new ConnectedInboxesPanel(providers, monitoringService, appConfig);
        this.queuePanel = new InvestigationQueuePanel(caseRepository, monitoringService, reportGenerator);
        this.urlPanel = new UrlDomainAnalysisPanel(detectionEngine.getThreatIntelService());
        this.casesPanel = new CasesPanel(caseRepository);
        this.threatPanel = new ThreatIntelligencePanel(detectionEngine.getThreatIntelService());
        this.evidencePanel = new EvidenceReportsPanel(caseRepository, reportGenerator);
        this.settingsPanel = new SettingsSecurityPanel(appConfig, credentialStore, providers, () -> {
            inboxesPanel.refreshStatus();
            dashboardPanel.refreshData();
        });
        this.aboutPanel = new AboutHelpPanel();

        contentStage.add(dashboardPanel, "DASHBOARD");
        contentStage.add(analyzePanel, "ANALYZE");
        contentStage.add(inboxesPanel, "INBOXES");
        contentStage.add(queuePanel, "QUEUE");
        contentStage.add(urlPanel, "URL_INSPECT");
        contentStage.add(casesPanel, "CASES");
        contentStage.add(threatPanel, "THREAT_INTEL");
        contentStage.add(evidencePanel, "REPORTS");
        contentStage.add(settingsPanel, "SETTINGS");
        contentStage.add(aboutPanel, "ABOUT");

        // Construct Root Layout with Top Bar
        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(UiTheme.BG_DARK);

        JPanel centerWrapper = new JPanel(new BorderLayout());
        centerWrapper.setOpaque(false);
        centerWrapper.add(createTopBar(monitoringService), BorderLayout.NORTH);
        centerWrapper.add(contentStage, BorderLayout.CENTER);

        root.add(createSidebar(), BorderLayout.WEST);
        root.add(centerWrapper, BorderLayout.CENTER);
        root.add(createStatusBar(monitoringService), BorderLayout.SOUTH);

        setContentPane(root);
        switchScreen("DASHBOARD");
    }

    private JPanel createTopBar(MonitoringService monitoringService) {
        JPanel topBar = new JPanel(new BorderLayout(16, 0));
        topBar.setBackground(UiTheme.SIDEBAR_BG);
        topBar.setPreferredSize(new Dimension(0, 46));
        topBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, UiTheme.BORDER_COLOR),
                new EmptyBorder(8, 20, 8, 20)
        ));

        // Left: Current Breadcrumb & System Status
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        leftPanel.setOpaque(false);

        JLabel lblShieldIcon = new JLabel("● SOC LIVE");
        lblShieldIcon.setFont(UiTheme.FONT_BOLD);
        lblShieldIcon.setForeground(UiTheme.COLOR_LOW);

        JLabel lblSeparator = new JLabel("|");
        lblSeparator.setForeground(UiTheme.TEXT_MUTED);

        lblScreenBreadcrumb = new JLabel("Overview Dashboard");
        lblScreenBreadcrumb.setFont(UiTheme.FONT_REGULAR);
        lblScreenBreadcrumb.setForeground(UiTheme.TEXT_PRIMARY);

        leftPanel.add(lblShieldIcon);
        leftPanel.add(lblSeparator);
        leftPanel.add(lblScreenBreadcrumb);

        topBar.add(leftPanel, BorderLayout.WEST);
        return topBar;
    }

    private void triggerGlobalRefresh(JButton btn, MonitoringService monitoringService) {
        if (btn != null) {
            btn.setEnabled(false);
            btn.setText("↻ Refreshing All Emails...");
        }

        SwingWorker<Integer, Void> worker = new SwingWorker<>() {
            @Override
            protected Integer doInBackground() {
                int newCount = 0;
                if (monitoringService != null && monitoringService.hasAnyConnectedProvider()) {
                    newCount = monitoringService.triggerSyncAllConnected(25);
                }
                return newCount;
            }

            @Override
            protected void done() {
                try {
                    int newCount = get();
                    // Refresh all relevant active panels
                    if (dashboardPanel != null) dashboardPanel.refreshData();
                    if (queuePanel != null) queuePanel.refreshQueue();
                    if (casesPanel != null) casesPanel.refreshCases();
                    if (evidencePanel != null) evidencePanel.refreshEvidence();
                    if (inboxesPanel != null) inboxesPanel.refreshStatus();

                    int totalCount = caseRepository != null ? caseRepository.getTotalEmailCount() : 0;
                    if (newCount > 0) {
                        JOptionPane.showMessageDialog(MailShieldMainWindow.this,
                                "✓ Inboxes Refreshed Successfully!\n\n" +
                                "Ingested and analyzed: " + newCount + " new email(s).\n" +
                                "Total emails in repository: " + totalCount + ".\n\n" +
                                "All active views, threat indicators, and investigation queues have been updated.",
                                "Refresh Complete", JOptionPane.INFORMATION_MESSAGE);
                    } else if (monitoringService != null && monitoringService.hasAnyConnectedProvider()) {
                        JOptionPane.showMessageDialog(MailShieldMainWindow.this,
                                "✓ Inboxes Up-to-Date\n\n" +
                                "Connected mailboxes were synchronized. No new incoming messages found.\n" +
                                "Total emails in repository: " + totalCount + ".",
                                "All Emails Refreshed", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(MailShieldMainWindow.this,
                                "✓ All Emails Refreshed\n\n" +
                                "Loaded " + totalCount + " email record(s) from local forensic database.\n\n" +
                                "ℹ To fetch live incoming emails from Google Gmail or Microsoft 365,\n" +
                                "please connect an inbox in 'Connected Inboxes' (Screen 3).",
                                "All Emails Refreshed", JOptionPane.INFORMATION_MESSAGE);
                    }
                } catch (Exception ex) {
                    if (dashboardPanel != null) dashboardPanel.refreshData();
                    if (queuePanel != null) queuePanel.refreshQueue();
                    JOptionPane.showMessageDialog(MailShieldMainWindow.this,
                            "Error during email synchronization: " + ex.getMessage(),
                            "Refresh Warning", JOptionPane.WARNING_MESSAGE);
                } finally {
                    if (btn != null) {
                        btn.setEnabled(true);
                        btn.setText("↻ Refresh All Emails");
                    }
                }
            }
        };
        worker.execute();
    }

    private JPanel createSidebar() {
        JPanel sidebar = new JPanel();
        sidebar.setLayout(new BoxLayout(sidebar, BoxLayout.Y_AXIS));
        sidebar.setBackground(UiTheme.SIDEBAR_BG);
        sidebar.setPreferredSize(new Dimension(240, 0));
        sidebar.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, UiTheme.BORDER_COLOR));

        // ── Logo / Brand block ──────────────────────────────────────────
        JPanel brandBlock = new JPanel();
        brandBlock.setLayout(new BoxLayout(brandBlock, BoxLayout.Y_AXIS));
        brandBlock.setBackground(new Color(0x07, 0x0C, 0x14));   // slightly deeper than sidebar
        brandBlock.setAlignmentX(Component.LEFT_ALIGNMENT);
        brandBlock.setMaximumSize(new Dimension(240, 90));
        brandBlock.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(0x38, 0xBD, 0xF8, 60)),
                new EmptyBorder(18, 18, 14, 18)
        ));

        // Shield emoji + name on one line
        JPanel logoRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        logoRow.setOpaque(false);
        logoRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel logoIcon = new JLabel("🛡");
        logoIcon.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 26));

        JPanel logoText = new JPanel();
        logoText.setLayout(new BoxLayout(logoText, BoxLayout.Y_AXIS));
        logoText.setOpaque(false);

        JLabel brandName = new JLabel("MailShield");
        brandName.setFont(new Font("Segoe UI", Font.BOLD, 17));
        brandName.setForeground(UiTheme.TEXT_PRIMARY);

        JLabel brandTagline = new JLabel("SOC Threat Detection");
        brandTagline.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        brandTagline.setForeground(UiTheme.ACCENT_CYAN);

        logoText.add(brandName);
        logoText.add(brandTagline);

        logoRow.add(logoIcon);
        logoRow.add(logoText);
        brandBlock.add(logoRow);

        // Version badge row
        JPanel badgeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        badgeRow.setOpaque(false);
        badgeRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        badgeRow.setBorder(new EmptyBorder(6, 2, 0, 0));

        JLabel badge = new JLabel("  v1.0  LIVE  ");
        badge.setFont(new Font("Consolas", Font.BOLD, 10));
        badge.setForeground(new Color(0x10, 0xB9, 0x81));
        badge.setBackground(new Color(0x05, 0x25, 0x1A));
        badge.setOpaque(true);
        badge.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x10, 0xB9, 0x81, 100), 1),
                new EmptyBorder(1, 4, 1, 4)
        ));
        badgeRow.add(badge);
        brandBlock.add(badgeRow);

        sidebar.add(brandBlock);

        // ── Section label ───────────────────────────────────────────────
        sidebar.add(createSectionLabel("NAVIGATION"));

        // ── Nav items with icons ────────────────────────────────────────
        addNavButton(sidebar, "DASHBOARD",    "⬛", "Overview Dashboard");
        addNavButton(sidebar, "ANALYZE",      "📧", "Analyze Email");
        addNavButton(sidebar, "INBOXES",      "📬", "Connected Inboxes");
        addNavButton(sidebar, "QUEUE",        "📋", "Investigation Queue");
        addNavButton(sidebar, "URL_INSPECT",  "🔗", "URL & Domain Forensics");
        addNavButton(sidebar, "CASES",        "📁", "Investigation Cases");

        sidebar.add(createSectionLabel("INTEL & ADMIN"));

        addNavButton(sidebar, "THREAT_INTEL", "⚠", "Threat Intelligence");
        addNavButton(sidebar, "REPORTS",      "📊", "Evidence & Reports");
        addNavButton(sidebar, "SETTINGS",     "⚙", "Settings & Security");
        addNavButton(sidebar, "ABOUT",        "❓", "Help & Documentation");

        sidebar.add(Box.createVerticalGlue());

        // ── Bottom status pill ──────────────────────────────────────────
        JPanel bottomPill = new JPanel(new BorderLayout());
        bottomPill.setOpaque(false);
        bottomPill.setBorder(new EmptyBorder(8, 14, 14, 14));
        bottomPill.setAlignmentX(Component.LEFT_ALIGNMENT);
        bottomPill.setMaximumSize(new Dimension(240, 50));

        JLabel lblEngine = new JLabel("● Engine Active  |  JDK 21 LTS");
        lblEngine.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        lblEngine.setForeground(new Color(0x64, 0x74, 0x8B));
        bottomPill.add(lblEngine, BorderLayout.CENTER);

        sidebar.add(bottomPill);

        return sidebar;
    }

    /** Small uppercase section divider label. */
    private JPanel createSectionLabel(String text) {
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setOpaque(false);
        wrapper.setMaximumSize(new Dimension(240, 30));
        wrapper.setAlignmentX(Component.LEFT_ALIGNMENT);
        wrapper.setBorder(new EmptyBorder(10, 16, 2, 16));

        JLabel lbl = new JLabel(text);
        lbl.setFont(new Font("Segoe UI", Font.BOLD, 10));
        lbl.setForeground(new Color(0x47, 0x55, 0x69));   // very muted grey
        wrapper.add(lbl, BorderLayout.WEST);
        return wrapper;
    }

    private void addNavButton(JPanel sidebar, String screenKey, String icon, String label) {
        JButton btn = new JButton() {
            @Override
            protected void paintComponent(Graphics g) {
                // Active state: left cyan accent bar + subtle highlight
                boolean active = UiTheme.ACCENT_CYAN.equals(getForeground())
                        && !UiTheme.TEXT_MUTED.equals(getForeground());
                if (getBackground() != UiTheme.SIDEBAR_BG) {
                    Graphics2D g2 = (Graphics2D) g;
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                    // Highlight background
                    g2.setColor(new Color(0x1E, 0x29, 0x3B, 180));
                    g2.fillRoundRect(4, 2, getWidth() - 8, getHeight() - 4, 8, 8);
                    // Left cyan indicator strip
                    g2.setColor(UiTheme.ACCENT_CYAN);
                    g2.fillRoundRect(0, 6, 3, getHeight() - 12, 3, 3);
                }
                super.paintComponent(g);
            }
        };

        // Build icon + label HTML
        btn.setText("<html><table cellpadding='0' cellspacing='0'><tr>"
                + "<td style='font-size:13px;padding-right:9px'>" + icon + "</td>"
                + "<td style='font-size:12px'>" + label + "</td>"
                + "</tr></table></html>");

        btn.setMaximumSize(new Dimension(236, 38));
        btn.setPreferredSize(new Dimension(236, 38));
        btn.setMinimumSize(new Dimension(100, 38));
        btn.setFont(UiTheme.FONT_REGULAR);
        btn.setForeground(UiTheme.TEXT_MUTED);
        btn.setBackground(UiTheme.SIDEBAR_BG);
        btn.setHorizontalAlignment(SwingConstants.LEFT);
        btn.setBorder(new EmptyBorder(5, 14, 5, 10));
        btn.setFocusPainted(false);
        btn.setContentAreaFilled(false);   // we do custom painting
        btn.setOpaque(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        // Hover effect
        btn.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseEntered(java.awt.event.MouseEvent e) {
                if (btn.getBackground() == UiTheme.SIDEBAR_BG) {   // not active
                    btn.setForeground(UiTheme.TEXT_PRIMARY);
                }
            }
            @Override public void mouseExited(java.awt.event.MouseEvent e) {
                if (btn.getBackground() == UiTheme.SIDEBAR_BG) {
                    btn.setForeground(UiTheme.TEXT_MUTED);
                }
            }
        });

        btn.addActionListener(e -> switchScreen(screenKey));

        navButtons.put(screenKey, btn);
        sidebar.add(btn);
        sidebar.add(Box.createVerticalStrut(2));
    }

    private void switchScreen(String screenKey) {
        cardLayout.show(contentStage, screenKey);

        String screenTitle = switch (screenKey) {
            case "DASHBOARD" -> "Overview Dashboard";
            case "ANALYZE" -> "Deep Email Ingestion & Static Analysis";
            case "INBOXES" -> "Connected Cloud Inboxes (OAuth2)";
            case "QUEUE" -> "Email Investigation & Triage Queue";
            case "URL_INSPECT" -> "URL & Domain Forensics";
            case "CASES" -> "Incident Investigation Cases";
            case "THREAT_INTEL" -> "Threat Intelligence & Curated Feeds";
            case "REPORTS" -> "Forensics Evidence & Chain of Custody";
            case "SETTINGS" -> "Platform Security & Settings";
            case "ABOUT" -> "Academic Viva Guide & Threat Model";
            default -> "Operations Console";
        };
        if (lblScreenBreadcrumb != null) {
            lblScreenBreadcrumb.setText(screenTitle);
        }

        for (Map.Entry<String, JButton> entry : navButtons.entrySet()) {
            boolean active = entry.getKey().equals(screenKey);
            JButton b = entry.getValue();
            b.setBackground(active ? UiTheme.CARD_BG : UiTheme.SIDEBAR_BG);
            b.setForeground(active ? UiTheme.ACCENT_CYAN : UiTheme.TEXT_MUTED);
            b.setFont(active ? UiTheme.FONT_BOLD : UiTheme.FONT_REGULAR);
            b.repaint();
        }

        // Auto-refresh data on panel switches
        if ("DASHBOARD".equals(screenKey) && dashboardPanel != null) {
            dashboardPanel.refreshData();
        } else if ("QUEUE".equals(screenKey) && queuePanel != null) {
            queuePanel.refreshQueue();
        } else if ("CASES".equals(screenKey) && casesPanel != null) {
            casesPanel.refreshCases();
        } else if ("REPORTS".equals(screenKey) && evidencePanel != null) {
            evidencePanel.refreshEvidence();
        } else if ("INBOXES".equals(screenKey) && inboxesPanel != null) {
            inboxesPanel.refreshStatus();
        }
    }

    private JPanel createStatusBar(MonitoringService monitoringService) {
        JPanel status = new JPanel(new BorderLayout());
        status.setBackground(UiTheme.SIDEBAR_BG);
        status.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, UiTheme.BORDER_COLOR),
                new EmptyBorder(6, 16, 6, 16)
        ));

        lblStatusProvider = new JLabel("● Storage: SQLite Encrypted Local DB (data/mailshield.db) — Ready");
        lblStatusProvider.setFont(UiTheme.FONT_SMALL);
        lblStatusProvider.setForeground(UiTheme.TEXT_MUTED);

        var monStatus = monitoringService != null ? monitoringService.getStatus() : null;
        String monText = monStatus != null ? "Monitoring: " + monStatus.getState().getDisplay() : "Monitoring: Standby";
        lblStatusMonitoring = new JLabel(monText + "  |  MailShield Engine v2.1.0  |  JDK 21 LTS");
        lblStatusMonitoring.setFont(UiTheme.FONT_SMALL);
        lblStatusMonitoring.setForeground(UiTheme.TEXT_MUTED);

        status.add(lblStatusProvider, BorderLayout.WEST);
        status.add(lblStatusMonitoring, BorderLayout.EAST);
        return status;
    }
}

