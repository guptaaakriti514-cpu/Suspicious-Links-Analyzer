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

    private final Map<ProviderType, EmailProvider> providers;
    private JButton btnTopLogout;

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
        this.providers = providers;

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1280, 820);
        setMinimumSize(new Dimension(1024, 700));
        setLocationRelativeTo(null);

        UiTheme.setupFlatLaf();

        // Initialize 10 Screens
        this.dashboardPanel = new DashboardPanel(caseRepository, providers, monitoringService, reportGenerator,
                () -> switchScreen("ANALYZE"),
                () -> switchScreen("INBOXES"));
        this.analyzePanel = new AnalyzeEmailPanel(emailParser, detectionEngine, caseRepository, evidenceManager, reportGenerator);
        this.inboxesPanel = new ConnectedInboxesPanel(providers, monitoringService, appConfig, () -> {
            if (dashboardPanel != null) dashboardPanel.refreshData();
            updateTopBarAccountStatus();
        });
        this.queuePanel = new InvestigationQueuePanel(caseRepository, monitoringService, reportGenerator);
        this.urlPanel = new UrlDomainAnalysisPanel(detectionEngine.getThreatIntelService());
        this.casesPanel = new CasesPanel(caseRepository);
        this.threatPanel = new ThreatIntelligencePanel(detectionEngine.getThreatIntelService());
        this.evidencePanel = new EvidenceReportsPanel(caseRepository, reportGenerator);
        this.settingsPanel = new SettingsSecurityPanel(appConfig, credentialStore, providers, () -> {
            inboxesPanel.refreshStatus();
            dashboardPanel.refreshData();
            updateTopBarAccountStatus();
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
        updateTopBarAccountStatus();
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

        // Right: Universal Log Out Button
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 0));
        rightPanel.setOpaque(false);

        btnTopLogout = UiTheme.createStyledButton("⎋ Log Out / Switch Account", UiTheme.CARD_BG);
        btnTopLogout.setBorder(BorderFactory.createLineBorder(UiTheme.COLOR_CRITICAL, 1));
        btnTopLogout.setForeground(UiTheme.COLOR_CRITICAL);
        btnTopLogout.setFont(UiTheme.FONT_SMALL);
        btnTopLogout.setPreferredSize(new Dimension(190, 28));
        btnTopLogout.setToolTipText("Log out and revoke tokens to switch accounts or providers");
        btnTopLogout.addActionListener(e -> handleLogoutAndSwitchAccount());

        rightPanel.add(btnTopLogout);

        topBar.add(leftPanel, BorderLayout.WEST);
        topBar.add(rightPanel, BorderLayout.EAST);
        return topBar;
    }

    public void updateTopBarAccountStatus() {
        if (providers == null || btnTopLogout == null) return;
        boolean hasAny = false;
        for (EmailProvider p : providers.values()) {
            if (p.getStatus().isConnected()) {
                hasAny = true;
                break;
            }
        }
        btnTopLogout.setVisible(hasAny);
    }

    private void handleLogoutAndSwitchAccount() {
        if (providers == null) return;
        java.util.List<EmailProvider> connected = new java.util.ArrayList<>();
        StringBuilder accountList = new StringBuilder();
        for (EmailProvider p : providers.values()) {
            if (p.getStatus().isConnected()) {
                connected.add(p);
                accountList.append("• ").append(p.getProviderType().getTitle())
                        .append(": ").append(p.getStatus().getAccountEmail()).append("\n");
            }
        }

        if (connected.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "No email accounts are currently connected.\n\nRedirecting to Connected Inboxes to sign in...",
                    "No Active Account", JOptionPane.INFORMATION_MESSAGE);
            switchScreen("INBOXES");
            return;
        }

        int choice = JOptionPane.showConfirmDialog(this,
                "Do you want to log out and switch your connected email account?\n\n" +
                "Currently connected accounts:\n" + accountList + "\n" +
                "Logging out will safely revoke local tokens and clear cached credentials from the vault.",
                "Log Out & Switch Account",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);

        if (choice != JOptionPane.YES_OPTION) {
            return;
        }

        for (EmailProvider p : connected) {
            p.disconnect();
        }

        updateTopBarAccountStatus();
        if (inboxesPanel != null) inboxesPanel.refreshStatus();
        if (dashboardPanel != null) dashboardPanel.refreshData();

        switchScreen("INBOXES");

        JOptionPane.showMessageDialog(this,
                "✓ Successfully logged out!\n\n" +
                "You can now select and connect a new Gmail or Microsoft Outlook account.",
                "Logged Out",
                JOptionPane.INFORMATION_MESSAGE);
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
                    updateTopBarAccountStatus();

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
                        btn.setText("↻ Refresh Emails");
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
        sidebar.setPreferredSize(new Dimension(248, 0));
        sidebar.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, new Color(0x1C, 0x27, 0x38)));

        // ════════════════════════════════════════════════════════════════
        //  BRAND HEADER — premium shield logo block
        // ════════════════════════════════════════════════════════════════
        JPanel brand = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                // Subtle gradient bottom glow
                GradientPaint gp = new GradientPaint(0, getHeight() - 6, new Color(0x38, 0xBD, 0xF8, 25), 0, getHeight(), new Color(0x38, 0xBD, 0xF8, 0));
                g2.setPaint(gp);
                g2.fillRect(0, getHeight() - 6, getWidth(), 6);
            }
        };
        brand.setLayout(new BoxLayout(brand, BoxLayout.Y_AXIS));
        brand.setBackground(new Color(0x06, 0x0A, 0x12));
        brand.setAlignmentX(Component.LEFT_ALIGNMENT);
        brand.setMaximumSize(new Dimension(248, 88));
        brand.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(0x1C, 0x27, 0x38)),
                new EmptyBorder(16, 18, 10, 18)
        ));

        // Logo row: shield icon + app name + tagline
        JPanel logoRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        logoRow.setOpaque(false);
        logoRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Circular shield emblem
        JLabel shieldIcon = new JLabel("🛡") {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(new Color(0x0E, 0x1C, 0x36));
                g2.fillOval(0, 0, 36, 36);
                g2.setColor(new Color(0x38, 0xBD, 0xF8, 60));
                g2.drawOval(0, 0, 35, 35);
                super.paintComponent(g);
            }
        };
        shieldIcon.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 20));
        shieldIcon.setHorizontalAlignment(SwingConstants.CENTER);
        shieldIcon.setPreferredSize(new Dimension(36, 36));

        JPanel nameCol = new JPanel();
        nameCol.setLayout(new BoxLayout(nameCol, BoxLayout.Y_AXIS));
        nameCol.setOpaque(false);

        JLabel appName = new JLabel("MAILSHIELD");
        appName.setFont(new Font("Segoe UI", Font.BOLD, 15));
        appName.setForeground(UiTheme.TEXT_PRIMARY);

        JLabel appTagline = new JLabel("Threat Detection Platform");
        appTagline.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        appTagline.setForeground(new Color(0x64, 0x9C, 0xCA));

        nameCol.add(appName);
        nameCol.add(Box.createVerticalStrut(1));
        nameCol.add(appTagline);

        logoRow.add(shieldIcon);
        logoRow.add(nameCol);
        brand.add(logoRow);

        // Version + status badges
        JPanel badgeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        badgeRow.setOpaque(false);
        badgeRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        badgeRow.setBorder(new EmptyBorder(6, 2, 0, 0));

        JLabel verBadge = new JLabel(" v1.0.0 ");
        verBadge.setFont(new Font("Consolas", Font.PLAIN, 9));
        verBadge.setForeground(new Color(0x94, 0xA3, 0xB8));
        verBadge.setBackground(new Color(0x14, 0x1C, 0x2E));
        verBadge.setOpaque(true);
        verBadge.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x2A, 0x38, 0x4E), 1),
                new EmptyBorder(1, 4, 1, 4)));

        JLabel liveBadge = new JLabel(" ● LIVE ");
        liveBadge.setFont(new Font("Consolas", Font.BOLD, 9));
        liveBadge.setForeground(new Color(0x10, 0xB9, 0x81));
        liveBadge.setBackground(new Color(0x05, 0x1E, 0x14));
        liveBadge.setOpaque(true);
        liveBadge.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x10, 0xB9, 0x81, 70), 1),
                new EmptyBorder(1, 4, 1, 4)));

        badgeRow.add(verBadge);
        badgeRow.add(liveBadge);
        brand.add(badgeRow);
        sidebar.add(brand);

        // ════════════════════════════════════════════════════════════════
        //  NAVIGATION — Core operational screens
        // ════════════════════════════════════════════════════════════════
        sidebar.add(createSectionDivider("NAVIGATION"));

        addNavItem(sidebar, "DASHBOARD",   "◈", "Overview Dashboard");
        addNavItem(sidebar, "ANALYZE",     "✉", "Analyze Email");
        addNavItem(sidebar, "INBOXES",     "⇄", "Connected Inboxes");
        addNavItem(sidebar, "QUEUE",       "☰", "Investigation Queue");
        addNavItem(sidebar, "URL_INSPECT", "⛓", "URL & Domain Forensics");
        addNavItem(sidebar, "CASES",       "▤", "Investigation Cases");

        // ════════════════════════════════════════════════════════════════
        //  INTEL — Threat intelligence & evidence
        // ════════════════════════════════════════════════════════════════
        sidebar.add(createSectionDivider("INTEL"));

        addNavItem(sidebar, "THREAT_INTEL", "◉", "Threat Intelligence");
        addNavItem(sidebar, "REPORTS",      "▦", "Evidence & Reports");

        // ════════════════════════════════════════════════════════════════
        //  ADMIN — Platform management
        // ════════════════════════════════════════════════════════════════
        sidebar.add(createSectionDivider("ADMIN"));

        addNavItem(sidebar, "SETTINGS", "⚙", "Settings & Security");
        addNavItem(sidebar, "ABOUT",    "?", "Help & Documentation");

        sidebar.add(Box.createVerticalGlue());

        // ════════════════════════════════════════════════════════════════
        //  FOOTER — Engine status indicator
        // ════════════════════════════════════════════════════════════════
        JPanel footer = new JPanel(new BorderLayout());
        footer.setBackground(new Color(0x06, 0x0A, 0x12));
        footer.setMaximumSize(new Dimension(248, 42));
        footer.setAlignmentX(Component.LEFT_ALIGNMENT);
        footer.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(0x1C, 0x27, 0x38)),
                new EmptyBorder(8, 16, 8, 16)
        ));

        JLabel engineLbl = new JLabel("● Engine Active");
        engineLbl.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        engineLbl.setForeground(new Color(0x10, 0xB9, 0x81));

        JLabel jdkLbl = new JLabel("JDK 21 LTS");
        jdkLbl.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        jdkLbl.setForeground(new Color(0x47, 0x55, 0x69));

        footer.add(engineLbl, BorderLayout.WEST);
        footer.add(jdkLbl, BorderLayout.EAST);
        sidebar.add(footer);

        return sidebar;
    }

    /**
     * Section divider: thin line + uppercase label — premium SOC style.
     */
    private JPanel createSectionDivider(String text) {
        JPanel wrapper = new JPanel(new BorderLayout(8, 0));
        wrapper.setOpaque(false);
        wrapper.setMaximumSize(new Dimension(248, 32));
        wrapper.setAlignmentX(Component.LEFT_ALIGNMENT);
        wrapper.setBorder(new EmptyBorder(12, 18, 4, 18));

        JLabel lbl = new JLabel(text);
        lbl.setFont(new Font("Segoe UI", Font.BOLD, 9));
        lbl.setForeground(new Color(0x47, 0x55, 0x69));

        // Horizontal hairline after text
        JPanel line = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                g.setColor(new Color(0x1C, 0x27, 0x38));
                g.drawLine(0, getHeight() / 2, getWidth(), getHeight() / 2);
            }
        };
        line.setOpaque(false);

        wrapper.add(lbl, BorderLayout.WEST);
        wrapper.add(line, BorderLayout.CENTER);
        return wrapper;
    }

    /**
     * Premium nav item with custom-painted active indicator, hover tint, and icon.
     */
    private void addNavItem(JPanel sidebar, String screenKey, String icon, String label) {
        final Color HOVER_BG   = new Color(0x12, 0x1A, 0x2D);
        final Color ACTIVE_BG  = new Color(0x14, 0x20, 0x36);
        final Color INDICATOR  = new Color(0x38, 0xBD, 0xF8);  // cyan accent strip

        JButton btn = new JButton() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g;
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

                boolean isActive = getBackground().equals(ACTIVE_BG);

                // Background fill for active / hovered state
                if (isActive) {
                    g2.setColor(ACTIVE_BG);
                    g2.fillRoundRect(6, 1, getWidth() - 12, getHeight() - 2, 8, 8);
                    // Left cyan indicator strip
                    g2.setColor(INDICATOR);
                    g2.fillRoundRect(2, 6, 3, getHeight() - 12, 3, 3);
                }

                super.paintComponent(g);
            }
        };

        // Icon + label via HTML table for crisp alignment
        btn.setText("<html><table cellpadding='0' cellspacing='0'><tr>"
                + "<td width='22' align='center' style='font-size:13px; color:#64748b;'>" + icon + "</td>"
                + "<td style='padding-left:8px; font-family:Segoe UI; font-size:11.5px;'>" + label + "</td>"
                + "</tr></table></html>");

        btn.setMaximumSize(new Dimension(244, 36));
        btn.setPreferredSize(new Dimension(244, 36));
        btn.setMinimumSize(new Dimension(100, 36));
        btn.setFont(UiTheme.FONT_REGULAR);
        btn.setForeground(UiTheme.TEXT_MUTED);
        btn.setBackground(UiTheme.SIDEBAR_BG);
        btn.setHorizontalAlignment(SwingConstants.LEFT);
        btn.setBorder(new EmptyBorder(4, 10, 4, 10));
        btn.setFocusPainted(false);
        btn.setContentAreaFilled(false);
        btn.setOpaque(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        // Hover effect — subtle background tint
        btn.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseEntered(java.awt.event.MouseEvent e) {
                if (!btn.getBackground().equals(ACTIVE_BG)) {
                    btn.setForeground(UiTheme.TEXT_PRIMARY);
                    btn.setBackground(HOVER_BG);
                    btn.repaint();
                }
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent e) {
                if (!btn.getBackground().equals(ACTIVE_BG)) {
                    btn.setForeground(UiTheme.TEXT_MUTED);
                    btn.setBackground(UiTheme.SIDEBAR_BG);
                    btn.repaint();
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

        final Color ACTIVE_BG = new Color(0x14, 0x20, 0x36);

        String screenTitle = switch (screenKey) {
            case "DASHBOARD"    -> "Overview Dashboard";
            case "ANALYZE"      -> "Deep Email Ingestion & Static Analysis";
            case "INBOXES"      -> "Connected Cloud Inboxes (OAuth2)";
            case "QUEUE"        -> "Email Investigation & Triage Queue";
            case "URL_INSPECT"  -> "URL & Domain Forensics";
            case "CASES"        -> "Incident Investigation Cases";
            case "THREAT_INTEL" -> "Threat Intelligence & Curated Feeds";
            case "REPORTS"      -> "Forensics Evidence & Chain of Custody";
            case "SETTINGS"     -> "Platform Security & Settings";
            case "ABOUT"        -> "Help & System Documentation";
            default             -> "Operations Console";
        };
        if (lblScreenBreadcrumb != null) {
            lblScreenBreadcrumb.setText(screenTitle);
        }

        for (Map.Entry<String, JButton> entry : navButtons.entrySet()) {
            boolean active = entry.getKey().equals(screenKey);
            JButton b = entry.getValue();
            b.setBackground(active ? ACTIVE_BG : UiTheme.SIDEBAR_BG);
            b.setForeground(active ? UiTheme.ACCENT_CYAN : UiTheme.TEXT_MUTED);
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

