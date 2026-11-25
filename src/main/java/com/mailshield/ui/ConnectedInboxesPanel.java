package com.mailshield.ui;

import com.mailshield.config.AppConfig;
import com.mailshield.model.ProviderConnectionStatus;
import com.mailshield.model.ProviderType;
import com.mailshield.monitoring.MonitoringService;
import com.mailshield.providers.EmailProvider;
import com.mailshield.providers.GmailProvider;
import com.mailshield.providers.OutlookProvider;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/**
 * Screen 3: Connected Cloud Inboxes & Onboarding Management.
 * Seamless, 1-click enterprise OAuth 2.0 PKCE mailbox integration.
 * Users connect Google Gmail or Microsoft 365 directly through official vendor identity portals.
 * Eliminates manual API keys or technical token configuration for end-users.
 */
public class ConnectedInboxesPanel extends JPanel {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault());

    private final Map<ProviderType, EmailProvider> providers;
    private final MonitoringService monitoringService;
    private final AppConfig appConfig;
    private final Runnable onAccountChanged;

    private JLabel lblGmailStatus;
    private JLabel lblGmailIdentity;
    private JLabel lblGmailLastSync;
    private JButton btnGmailConnect;
    private JButton btnGmailSync;
    private JButton btnGmailDisconnect;

    private JLabel lblOutlookStatus;
    private JLabel lblOutlookIdentity;
    private JLabel lblOutlookLastSync;
    private JButton btnOutlookConnect;
    private JButton btnOutlookSync;
    private JButton btnOutlookDisconnect;

    public ConnectedInboxesPanel(Map<ProviderType, EmailProvider> providers,
                                 MonitoringService monitoringService,
                                 AppConfig appConfig,
                                 Runnable onAccountChanged) {
        this.providers = providers;
        this.monitoringService = monitoringService;
        this.appConfig = appConfig != null ? appConfig : AppConfig.getInstance();
        this.onAccountChanged = onAccountChanged;

        setLayout(new BorderLayout(16, 20));
        setBackground(UiTheme.BG_DARK);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initHeader();
        initCards();
        refreshStatus();
    }

    public ConnectedInboxesPanel(Map<ProviderType, EmailProvider> providers,
                                 MonitoringService monitoringService,
                                 AppConfig appConfig) {
        this(providers, monitoringService, appConfig, null);
    }

    public ConnectedInboxesPanel(Map<ProviderType, EmailProvider> providers, MonitoringService monitoringService) {
        this(providers, monitoringService, AppConfig.getInstance(), null);
    }

    private void initHeader() {
        JPanel header = new JPanel(new BorderLayout(16, 0));
        header.setOpaque(false);

        JPanel text = new JPanel(new GridLayout(2, 1, 0, 4));
        text.setOpaque(false);

        JLabel title = new JLabel("Secure your inbox with MailShield.");
        title.setFont(UiTheme.FONT_TITLE);
        title.setForeground(UiTheme.TEXT_PRIMARY);

        JLabel subtitle = new JLabel("Connect your email account and let MailShield analyze suspicious messages, detect phishing attempts, and protect your digital identity.");
        subtitle.setFont(UiTheme.FONT_SMALL);
        subtitle.setForeground(UiTheme.TEXT_MUTED);

        text.add(title);
        text.add(subtitle);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        btnPanel.setOpaque(false);

        JButton btnSyncAll = UiTheme.createStyledButton("↻ Sync Inboxes Now", UiTheme.ACCENT_BLUE);
        btnSyncAll.setToolTipText("Fetch and analyze new incoming messages from all authorized accounts");
        btnSyncAll.addActionListener(e -> syncAllInboxes(btnSyncAll));

        btnPanel.add(btnSyncAll);

        header.add(text, BorderLayout.WEST);
        header.add(btnPanel, BorderLayout.EAST);
        add(header, BorderLayout.NORTH);
    }

    private void syncAllInboxes(JButton btn) {
        if (monitoringService == null || !monitoringService.hasAnyConnectedProvider()) {
            JOptionPane.showMessageDialog(this,
                    "No email inboxes are currently connected.\n\n" +
                    "Please click 'Connect Gmail' or 'Connect Outlook' below to authorize an account.",
                    "No Connected Inboxes", JOptionPane.INFORMATION_MESSAGE);
            refreshStatus();
            return;
        }

        if (btn != null) {
            btn.setEnabled(false);
            btn.setText("↻ Syncing Inboxes...");
        }

        SwingWorker<Integer, Void> worker = new SwingWorker<>() {
            @Override
            protected Integer doInBackground() {
                return monitoringService.triggerSyncAllConnected(25);
            }

            @Override
            protected void done() {
                try {
                    int count = get();
                    refreshStatus();
                    if (onAccountChanged != null) onAccountChanged.run();
                    JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                            "✓ Synchronization pass completed successfully!\n\n" +
                            "Ingested and analyzed: " + count + " new email message(s).\n\n" +
                            "Inspect full forensics in 'Overview Dashboard' or 'Investigation Queue'.",
                            "Inboxes Synchronized", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    refreshStatus();
                    JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                            "Synchronization error: " + ex.getMessage(),
                            "Sync Failed", JOptionPane.ERROR_MESSAGE);
                } finally {
                    if (btn != null) {
                        btn.setEnabled(true);
                        btn.setText("↻ Sync Inboxes Now");
                    }
                }
            }
        };
        worker.execute();
    }

    private void initCards() {
        JPanel centerContainer = new JPanel(new BorderLayout(0, 18));
        centerContainer.setOpaque(false);

        JPanel content = new JPanel(new GridLayout(1, 2, 20, 0));
        content.setOpaque(false);

        // 1. Google Gmail Card
        content.add(createGmailCard());

        // 2. Microsoft Outlook / 365 Card
        content.add(createOutlookCard());

        centerContainer.add(content, BorderLayout.CENTER);

        // Bottom Consent and Security Guarantee
        JPanel bottomNotice = UiTheme.createCardPanel();
        bottomNotice.setLayout(new GridLayout(1, 4, 16, 0));

        bottomNotice.add(createSecurityPill("● Zero Password Handling", "Direct vendor OAuth 2.0 PKCE redirection. MailShield never handles passwords."));
        bottomNotice.add(createSecurityPill("● Strict Read-Only Scopes", "Limited strictly to gmail.readonly and Mail.Read. Never alters or sends mail."));
        bottomNotice.add(createSecurityPill("● AES-256-GCM Vault", "All session credentials & tokens encrypted at rest with authenticated encryption."));
        bottomNotice.add(createSecurityPill("● 100% Local Forensics", "Forensics and detection pipeline run locally on workstation without data leakage."));

        centerContainer.add(bottomNotice, BorderLayout.SOUTH);
        add(centerContainer, BorderLayout.CENTER);
    }

    private JPanel createSecurityPill(String title, String desc) {
        JPanel pill = new JPanel(new GridLayout(2, 1, 0, 4));
        pill.setOpaque(false);
        JLabel lblTitle = new JLabel(title);
        lblTitle.setFont(UiTheme.FONT_BOLD);
        lblTitle.setForeground(UiTheme.ACCENT_CYAN);
        JLabel lblDesc = new JLabel("<html><small style='color:#94a3b8;'>" + desc + "</small></html>");
        pill.add(lblTitle);
        pill.add(lblDesc);
        return pill;
    }

    private JPanel createGmailCard() {
        JPanel card = UiTheme.createCardPanel();
        card.setLayout(new BorderLayout(0, 16));

        // Top Section: Title & Description
        JPanel topSection = new JPanel();
        topSection.setLayout(new BoxLayout(topSection, BoxLayout.Y_AXIS));
        topSection.setOpaque(false);

        JPanel headerRow = new JPanel(new BorderLayout());
        headerRow.setOpaque(false);

        JLabel title = new JLabel("Google Gmail");
        title.setFont(UiTheme.FONT_HEADER);
        title.setForeground(UiTheme.ACCENT_CYAN);

        JLabel badge = new JLabel("Official OAuth 2.0 PKCE");
        badge.setFont(UiTheme.FONT_SMALL);
        badge.setForeground(UiTheme.TEXT_MUTED);

        headerRow.add(title, BorderLayout.WEST);
        headerRow.add(badge, BorderLayout.EAST);
        topSection.add(headerRow);
        topSection.add(Box.createVerticalStrut(6));

        JLabel desc = new JLabel("<html>Connect personal or Google Workspace accounts with 1-click official Google authorization. Scopes: <code>gmail.readonly</code>.</html>");
        desc.setFont(UiTheme.FONT_SMALL);
        desc.setForeground(UiTheme.TEXT_MUTED);
        topSection.add(desc);

        // Center Section: Status Display Box
        JPanel statusBox = new JPanel();
        statusBox.setLayout(new BoxLayout(statusBox, BoxLayout.Y_AXIS));
        statusBox.setBackground(UiTheme.BG_DARK);
        statusBox.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1),
                new EmptyBorder(14, 16, 14, 16)
        ));

        lblGmailStatus = new JLabel("Status: Disconnected");
        lblGmailStatus.setFont(UiTheme.FONT_REGULAR);

        lblGmailIdentity = new JLabel("Authorized Mailbox: Not connected");
        lblGmailIdentity.setFont(UiTheme.FONT_REGULAR);

        JLabel lblScope = new JLabel("Permissions: Read-Only Email Inspection (gmail.readonly)");
        lblScope.setFont(UiTheme.FONT_SMALL);
        lblScope.setForeground(UiTheme.TEXT_MUTED);

        lblGmailLastSync = new JLabel("Last Synchronized: Never");
        lblGmailLastSync.setFont(UiTheme.FONT_SMALL);
        lblGmailLastSync.setForeground(UiTheme.TEXT_MUTED);

        statusBox.add(lblGmailStatus);
        statusBox.add(Box.createVerticalStrut(8));
        statusBox.add(lblGmailIdentity);
        statusBox.add(Box.createVerticalStrut(8));
        statusBox.add(lblScope);
        statusBox.add(Box.createVerticalStrut(8));
        statusBox.add(lblGmailLastSync);

        // Bottom Section: Actions
        JPanel btnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        btnBar.setOpaque(false);

        btnGmailConnect = UiTheme.createStyledButton("Connect Gmail", UiTheme.ACCENT_BLUE);
        btnGmailConnect.setPreferredSize(new Dimension(170, 36));
        btnGmailConnect.addActionListener(e -> connectGmail());

        btnGmailSync = UiTheme.createStyledButton("↻ Sync Now", UiTheme.CARD_BG);
        btnGmailSync.setBorder(BorderFactory.createLineBorder(UiTheme.ACCENT_CYAN, 1));
        btnGmailSync.addActionListener(e -> syncProvider(ProviderType.GMAIL));

        btnGmailDisconnect = UiTheme.createStyledButton("Disconnect", UiTheme.CARD_BG);
        btnGmailDisconnect.setBorder(BorderFactory.createLineBorder(UiTheme.COLOR_CRITICAL, 1));
        btnGmailDisconnect.addActionListener(e -> disconnectProvider(ProviderType.GMAIL));

        btnBar.add(btnGmailConnect);
        btnBar.add(btnGmailSync);
        btnBar.add(btnGmailDisconnect);

        card.add(topSection, BorderLayout.NORTH);
        card.add(statusBox, BorderLayout.CENTER);
        card.add(btnBar, BorderLayout.SOUTH);

        return card;
    }

    private JPanel createOutlookCard() {
        JPanel card = UiTheme.createCardPanel();
        card.setLayout(new BorderLayout(0, 16));

        // Top Section: Title & Description
        JPanel topSection = new JPanel();
        topSection.setLayout(new BoxLayout(topSection, BoxLayout.Y_AXIS));
        topSection.setOpaque(false);

        JPanel headerRow = new JPanel(new BorderLayout());
        headerRow.setOpaque(false);

        JLabel title = new JLabel("Microsoft Outlook / 365");
        title.setFont(UiTheme.FONT_HEADER);
        title.setForeground(UiTheme.ACCENT_CYAN);

        JLabel badge = new JLabel("Microsoft Entra ID");
        badge.setFont(UiTheme.FONT_SMALL);
        badge.setForeground(UiTheme.TEXT_MUTED);

        headerRow.add(title, BorderLayout.WEST);
        headerRow.add(badge, BorderLayout.EAST);
        topSection.add(headerRow);
        topSection.add(Box.createVerticalStrut(6));

        JLabel desc = new JLabel("<html>Connect Outlook.com, Hotmail, or Microsoft 365 work accounts seamlessly via Microsoft Graph API. Scopes: <code>Mail.Read</code>.</html>");
        desc.setFont(UiTheme.FONT_SMALL);
        desc.setForeground(UiTheme.TEXT_MUTED);
        topSection.add(desc);

        // Center Section: Status Display Box
        JPanel statusBox = new JPanel();
        statusBox.setLayout(new BoxLayout(statusBox, BoxLayout.Y_AXIS));
        statusBox.setBackground(UiTheme.BG_DARK);
        statusBox.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1),
                new EmptyBorder(14, 16, 14, 16)
        ));

        lblOutlookStatus = new JLabel("Status: Disconnected");
        lblOutlookStatus.setFont(UiTheme.FONT_REGULAR);

        lblOutlookIdentity = new JLabel("Authorized Mailbox: Not connected");
        lblOutlookIdentity.setFont(UiTheme.FONT_REGULAR);

        JLabel lblScope = new JLabel("Permissions: Read-Only Email Inspection (Mail.Read)");
        lblScope.setFont(UiTheme.FONT_SMALL);
        lblScope.setForeground(UiTheme.TEXT_MUTED);

        lblOutlookLastSync = new JLabel("Last Synchronized: Never");
        lblOutlookLastSync.setFont(UiTheme.FONT_SMALL);
        lblOutlookLastSync.setForeground(UiTheme.TEXT_MUTED);

        statusBox.add(lblOutlookStatus);
        statusBox.add(Box.createVerticalStrut(8));
        statusBox.add(lblOutlookIdentity);
        statusBox.add(Box.createVerticalStrut(8));
        statusBox.add(lblScope);
        statusBox.add(Box.createVerticalStrut(8));
        statusBox.add(lblOutlookLastSync);

        // Bottom Section: Actions
        JPanel btnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        btnBar.setOpaque(false);

        btnOutlookConnect = UiTheme.createStyledButton("Connect Outlook", UiTheme.ACCENT_BLUE);
        btnOutlookConnect.setPreferredSize(new Dimension(170, 36));
        btnOutlookConnect.addActionListener(e -> connectOutlook());

        btnOutlookSync = UiTheme.createStyledButton("↻ Sync Now", UiTheme.CARD_BG);
        btnOutlookSync.setBorder(BorderFactory.createLineBorder(UiTheme.ACCENT_CYAN, 1));
        btnOutlookSync.addActionListener(e -> syncProvider(ProviderType.OUTLOOK));

        btnOutlookDisconnect = UiTheme.createStyledButton("Disconnect", UiTheme.CARD_BG);
        btnOutlookDisconnect.setBorder(BorderFactory.createLineBorder(UiTheme.COLOR_CRITICAL, 1));
        btnOutlookDisconnect.addActionListener(e -> disconnectProvider(ProviderType.OUTLOOK));

        btnBar.add(btnOutlookConnect);
        btnBar.add(btnOutlookSync);
        btnBar.add(btnOutlookDisconnect);

        card.add(topSection, BorderLayout.NORTH);
        card.add(statusBox, BorderLayout.CENTER);
        card.add(btnBar, BorderLayout.SOUTH);

        return card;
    }

    private void connectGmail() {
        EmailProvider provider = providers.get(ProviderType.GMAIL);
        if (provider instanceof GmailProvider gp) {
            lblGmailStatus.setText("Status: Opening web browser for Google sign-in...");
            lblGmailStatus.setForeground(UiTheme.ACCENT_CYAN);

            JDialog waitDialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Connecting Google Gmail...", false);
            waitDialog.setSize(440, 140);
            waitDialog.setLocationRelativeTo(this);
            JPanel p = new JPanel(new BorderLayout(12, 12));
            p.setBackground(UiTheme.BG_DARK);
            p.setBorder(new EmptyBorder(16, 20, 16, 20));
            JLabel lblMsg = new JLabel("<html><strong>Opening Google Sign-In...</strong><br/>Please select your account and authorize MailShield in your web browser.</html>");
            lblMsg.setFont(UiTheme.FONT_REGULAR);
            JProgressBar pb = new JProgressBar();
            pb.setIndeterminate(true);
            p.add(lblMsg, BorderLayout.CENTER);
            p.add(pb, BorderLayout.SOUTH);
            waitDialog.setContentPane(p);
            waitDialog.setVisible(true);

            SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
                @Override
                protected Boolean doInBackground() {
                    return gp.authenticate();
                }

                @Override
                protected void done() {
                    waitDialog.dispose();
                    try {
                        boolean success = get();
                        refreshStatus();
                        if (onAccountChanged != null) onAccountChanged.run();

                        if (success) {
                            JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                                    "✓ Google Gmail Account Connected Successfully!\n\n" +
                                    "Authorized Mailbox: " + gp.getStatus().getAccountEmail() + "\n" +
                                    "Security Scope: Read-Only (gmail.readonly)\n\n" +
                                    "MailShield is now monitoring your inbox for security threats.",
                                    "Google Gmail Connected", JOptionPane.INFORMATION_MESSAGE);
                        } else {
                            String err = gp.getLastErrorMessage();
                            if (err == null || err.isBlank()) err = "Authorization was cancelled or rejected by user.";
                            JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                                    "Google Gmail Connection Notice:\n\n" + err,
                                    "Connection Incomplete", JOptionPane.WARNING_MESSAGE);
                        }
                    } catch (Exception ex) {
                        refreshStatus();
                        JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                                "Error during Google OAuth flow: " + ex.getMessage(),
                                "Authentication Exception", JOptionPane.ERROR_MESSAGE);
                    }
                }
            };
            worker.execute();
        }
    }

    private void connectOutlook() {
        EmailProvider provider = providers.get(ProviderType.OUTLOOK);
        if (provider instanceof OutlookProvider op) {
            lblOutlookStatus.setText("Status: Opening web browser for Microsoft sign-in...");
            lblOutlookStatus.setForeground(UiTheme.ACCENT_CYAN);

            JDialog waitDialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Connecting Microsoft Outlook...", false);
            waitDialog.setSize(440, 140);
            waitDialog.setLocationRelativeTo(this);
            JPanel p = new JPanel(new BorderLayout(12, 12));
            p.setBackground(UiTheme.BG_DARK);
            p.setBorder(new EmptyBorder(16, 20, 16, 20));
            JLabel lblMsg = new JLabel("<html><strong>Opening Microsoft Sign-In...</strong><br/>Please sign in and authorize MailShield in your web browser.</html>");
            lblMsg.setFont(UiTheme.FONT_REGULAR);
            JProgressBar pb = new JProgressBar();
            pb.setIndeterminate(true);
            p.add(lblMsg, BorderLayout.CENTER);
            p.add(pb, BorderLayout.SOUTH);
            waitDialog.setContentPane(p);
            waitDialog.setVisible(true);

            SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
                @Override
                protected Boolean doInBackground() {
                    return op.authenticate();
                }

                @Override
                protected void done() {
                    waitDialog.dispose();
                    try {
                        boolean success = get();
                        refreshStatus();
                        if (onAccountChanged != null) onAccountChanged.run();

                        if (success) {
                            JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                                    "✓ Microsoft Outlook / 365 Connected Successfully!\n\n" +
                                    "Authorized Mailbox: " + op.getStatus().getAccountEmail() + "\n" +
                                    "Security Scope: Read-Only (Mail.Read)\n\n" +
                                    "MailShield is now monitoring your inbox for security threats.",
                                    "Microsoft Outlook Connected", JOptionPane.INFORMATION_MESSAGE);
                        } else {
                            String err = op.getLastErrorMessage();
                            if (err == null || err.isBlank()) err = "Authorization was cancelled or loopback timed out.";
                            JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                                    "Microsoft Outlook Connection Notice:\n\n" + err,
                                    "Connection Incomplete", JOptionPane.WARNING_MESSAGE);
                        }
                    } catch (Exception ex) {
                        refreshStatus();
                        JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                                "Error during Microsoft OAuth flow: " + ex.getMessage(),
                                "Authentication Exception", JOptionPane.ERROR_MESSAGE);
                    }
                }
            };
            worker.execute();
        }
    }

    private void syncProvider(ProviderType providerType) {
        if (monitoringService == null) return;
        EmailProvider provider = providers.get(providerType);
        if (provider == null || !provider.getStatus().isConnected()) {
            JOptionPane.showMessageDialog(this,
                    "Provider " + providerType.getTitle() + " is not connected yet.",
                    "Not Connected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        SwingWorker<Integer, Void> worker = new SwingWorker<>() {
            @Override
            protected Integer doInBackground() {
                return monitoringService.triggerSyncAllConnected(25);
            }

            @Override
            protected void done() {
                try {
                    int count = get();
                    refreshStatus();
                    if (onAccountChanged != null) onAccountChanged.run();
                    JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                            "✓ Synchronized " + count + " new email(s) from " + providerType.getTitle() + "!",
                            "Sync Complete", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                            "Sync error: " + e.getMessage(), "Sync Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }

    private void disconnectProvider(ProviderType providerType) {
        int opt = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to disconnect " + providerType.getTitle() + "?\n\n" +
                "This will revoke local session tokens and purge cached credentials from the AES-256 vault.",
                "Disconnect Account", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (opt != JOptionPane.YES_OPTION) return;

        EmailProvider provider = providers.get(providerType);
        if (provider != null) {
            provider.disconnect();
            refreshStatus();
            if (onAccountChanged != null) onAccountChanged.run();
            JOptionPane.showMessageDialog(this,
                    "✓ " + providerType.getTitle() + " has been safely disconnected.\n" +
                    "Local session tokens have been securely wiped.",
                    "Account Disconnected", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    public void refreshStatus() {
        // Gmail Card Update
        EmailProvider gp = providers.get(ProviderType.GMAIL);
        if (gp != null) {
            ProviderConnectionStatus status = gp.getStatus();
            boolean connected = status.isConnected();

            if (connected) {
                lblGmailStatus.setText("<html>Status: <strong style='color:#4ade80;'>● Connected & Active</strong></html>");
                lblGmailIdentity.setText("<html>Authorized Mailbox: <strong style='color:#38bdf8;'>" +
                        (status.getAccountEmail() != null ? status.getAccountEmail() : "Google Account") + "</strong></html>");
                btnGmailConnect.setVisible(false);
                btnGmailSync.setVisible(true);
                btnGmailDisconnect.setVisible(true);
            } else {
                lblGmailStatus.setText("<html>Status: <span style='color:#94a3b8;'>Disconnected (Not Signed In)</span></html>");
                lblGmailIdentity.setText("Authorized Mailbox: Not connected");
                btnGmailConnect.setVisible(true);
                btnGmailSync.setVisible(false);
                btnGmailDisconnect.setVisible(false);
            }

            if (status.getLastSyncTime() != null) {
                lblGmailLastSync.setText("Last Synchronized: " + TIME_FMT.format(status.getLastSyncTime()));
            } else {
                lblGmailLastSync.setText("Last Synchronized: Never");
            }
        }

        // Outlook Card Update
        EmailProvider op = providers.get(ProviderType.OUTLOOK);
        if (op != null) {
            ProviderConnectionStatus status = op.getStatus();
            boolean connected = status.isConnected();

            if (connected) {
                lblOutlookStatus.setText("<html>Status: <strong style='color:#4ade80;'>● Connected & Active</strong></html>");
                lblOutlookIdentity.setText("<html>Authorized Mailbox: <strong style='color:#38bdf8;'>" +
                        (status.getAccountEmail() != null ? status.getAccountEmail() : "Microsoft Account") + "</strong></html>");
                btnOutlookConnect.setVisible(false);
                btnOutlookSync.setVisible(true);
                btnOutlookDisconnect.setVisible(true);
            } else {
                lblOutlookStatus.setText("<html>Status: <span style='color:#94a3b8;'>Disconnected (Not Signed In)</span></html>");
                lblOutlookIdentity.setText("Authorized Mailbox: Not connected");
                btnOutlookConnect.setVisible(true);
                btnOutlookSync.setVisible(false);
                btnOutlookDisconnect.setVisible(false);
            }

            if (status.getLastSyncTime() != null) {
                lblOutlookLastSync.setText("Last Synchronized: " + TIME_FMT.format(status.getLastSyncTime()));
            } else {
                lblOutlookLastSync.setText("Last Synchronized: Never");
            }
        }

        revalidate();
        repaint();
    }
}
