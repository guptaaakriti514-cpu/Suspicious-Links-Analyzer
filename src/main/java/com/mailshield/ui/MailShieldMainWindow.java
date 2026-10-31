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
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1280, 820);
        setMinimumSize(new Dimension(1024, 700));
        setLocationRelativeTo(null);

        UiTheme.setupFlatLaf();

        // Initialize 10 Screens
        this.dashboardPanel = new DashboardPanel(caseRepository, providers, () -> switchScreen("ANALYZE"));
        this.analyzePanel = new AnalyzeEmailPanel(emailParser, detectionEngine, caseRepository, evidenceManager, reportGenerator);
        this.inboxesPanel = new ConnectedInboxesPanel(providers, monitoringService);
        this.queuePanel = new InvestigationQueuePanel(caseRepository);
        this.urlPanel = new UrlDomainAnalysisPanel(detectionEngine.getThreatIntelService());
        this.casesPanel = new CasesPanel(caseRepository);
        this.threatPanel = new ThreatIntelligencePanel(detectionEngine.getThreatIntelService());
        this.evidencePanel = new EvidenceReportsPanel(caseRepository, reportGenerator);
        this.settingsPanel = new SettingsSecurityPanel(appConfig, credentialStore);
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

        // Construct Root Layout
        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(UiTheme.BG_DARK);

        root.add(createSidebar(), BorderLayout.WEST);
        root.add(contentStage, BorderLayout.CENTER);
        root.add(createStatusBar(monitoringService), BorderLayout.SOUTH);

        setContentPane(root);
        switchScreen("DASHBOARD");
    }

    private JPanel createSidebar() {
        JPanel sidebar = new JPanel();
        sidebar.setLayout(new BoxLayout(sidebar, BoxLayout.Y_AXIS));
        sidebar.setBackground(UiTheme.SIDEBAR_BG);
        sidebar.setPreferredSize(new Dimension(230, 0));
        sidebar.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, UiTheme.BORDER_COLOR));

        // Brand Banner
        JPanel brandBox = new JPanel(new GridLayout(2, 1, 0, 2));
        brandBox.setBackground(UiTheme.SIDEBAR_BG);
        brandBox.setBorder(new EmptyBorder(18, 16, 18, 16));

        JLabel brandName = new JLabel("🛡 MAILSHIELD");
        brandName.setFont(new Font("Segoe UI", Font.BOLD, 16));
        brandName.setForeground(UiTheme.TEXT_PRIMARY);

        JLabel brandSub = new JLabel("SOC Forensics & Detection");
        brandSub.setFont(UiTheme.FONT_SMALL);
        brandSub.setForeground(UiTheme.ACCENT_CYAN);

        brandBox.add(brandName);
        brandBox.add(brandSub);
        sidebar.add(brandBox);
        sidebar.add(Box.createVerticalStrut(10));

        // Navigation Items
        addNavButton(sidebar, "1. Overview Dashboard", "DASHBOARD");
        addNavButton(sidebar, "2. Analyze Email", "ANALYZE");
        addNavButton(sidebar, "3. Connected Inboxes", "INBOXES");
        addNavButton(sidebar, "4. Investigation Queue", "QUEUE");
        addNavButton(sidebar, "5. URL & Domain Forensics", "URL_INSPECT");
        addNavButton(sidebar, "6. Investigation Cases", "CASES");
        addNavButton(sidebar, "7. Threat Intelligence", "THREAT_INTEL");
        addNavButton(sidebar, "8. Evidence & Reports", "REPORTS");
        addNavButton(sidebar, "9. Settings & Security", "SETTINGS");
        addNavButton(sidebar, "10. Help / Academic Viva", "ABOUT");

        sidebar.add(Box.createVerticalGlue());

        // Offline Academic Demo Mode pill
        JPanel vivaPill = new JPanel(new GridLayout(2, 1, 0, 2));
        vivaPill.setBackground(new Color(0x13, 0x1D, 0x31));
        vivaPill.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1),
                new EmptyBorder(8, 10, 8, 10)
        ));
        JLabel lblViva1 = new JLabel("Academic Viva Mode");
        lblViva1.setFont(UiTheme.FONT_BOLD);
        lblViva1.setForeground(UiTheme.ACCENT_CYAN);
        JLabel lblViva2 = new JLabel("Offline Fixtures Active");
        lblViva2.setFont(UiTheme.FONT_SMALL);
        lblViva2.setForeground(UiTheme.TEXT_MUTED);
        vivaPill.add(lblViva1);
        vivaPill.add(lblViva2);

        JPanel vivaWrapper = new JPanel(new BorderLayout());
        vivaWrapper.setOpaque(false);
        vivaWrapper.setBorder(new EmptyBorder(10, 12, 16, 12));
        vivaWrapper.add(vivaPill, BorderLayout.CENTER);
        sidebar.add(vivaWrapper);

        return sidebar;
    }

    private void addNavButton(JPanel sidebar, String label, String screenKey) {
        JButton btn = new JButton(label);
        btn.setMaximumSize(new Dimension(210, 34));
        btn.setPreferredSize(new Dimension(210, 34));
        btn.setFont(UiTheme.FONT_REGULAR);
        btn.setForeground(UiTheme.TEXT_MUTED);
        btn.setBackground(UiTheme.SIDEBAR_BG);
        btn.setHorizontalAlignment(SwingConstants.LEFT);
        btn.setBorder(new EmptyBorder(6, 16, 6, 16));
        btn.setFocusPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        btn.addActionListener(e -> switchScreen(screenKey));

        navButtons.put(screenKey, btn);
        sidebar.add(btn);
        sidebar.add(Box.createVerticalStrut(4));
    }

    private void switchScreen(String screenKey) {
        cardLayout.show(contentStage, screenKey);

        for (Map.Entry<String, JButton> entry : navButtons.entrySet()) {
            boolean active = entry.getKey().equals(screenKey);
            JButton b = entry.getValue();
            b.setBackground(active ? UiTheme.CARD_BG : UiTheme.SIDEBAR_BG);
            b.setForeground(active ? UiTheme.ACCENT_CYAN : UiTheme.TEXT_MUTED);
            b.setFont(active ? UiTheme.FONT_BOLD : UiTheme.FONT_REGULAR);
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

