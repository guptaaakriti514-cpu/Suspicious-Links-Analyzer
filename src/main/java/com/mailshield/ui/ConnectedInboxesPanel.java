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
 * Screen 3: Connected Cloud Inboxes Management.
 * Provides transparent, honest configuration and OAuth authorization cards for
 * Google Gmail API and Microsoft Outlook Graph API.
 * Supports direct in-GUI credentials configuration, live connection status, and instant feedback.
 */
public class ConnectedInboxesPanel extends JPanel {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault());

    private final Map<ProviderType, EmailProvider> providers;
    private final MonitoringService monitoringService;
    private final AppConfig appConfig;

    private JLabel lblGmailCredStatus;
    private JLabel lblGmailStatus;
    private JLabel lblGmailIdentity;
    private JLabel lblGmailLastSync;

    private JLabel lblOutlookCredStatus;
    private JLabel lblOutlookStatus;
    private JLabel lblOutlookIdentity;
    private JLabel lblOutlookLastSync;

    public ConnectedInboxesPanel(Map<ProviderType, EmailProvider> providers,
                                 MonitoringService monitoringService,
                                 AppConfig appConfig) {
        this.providers = providers;
        this.monitoringService = monitoringService;
        this.appConfig = appConfig != null ? appConfig : AppConfig.getInstance();

        setLayout(new BorderLayout(16, 20));
        setBackground(UiTheme.BG_DARK);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initHeader();
        initCards();
        refreshStatus();
    }

    public ConnectedInboxesPanel(Map<ProviderType, EmailProvider> providers, MonitoringService monitoringService) {
        this(providers, monitoringService, AppConfig.getInstance());
    }

    private void initHeader() {
        JPanel header = new JPanel(new GridLayout(2, 1, 0, 4));
        header.setOpaque(false);

        JLabel title = new JLabel("Authorized Mailbox Integrations");
        title.setFont(UiTheme.FONT_TITLE);

        JLabel subtitle = new JLabel("Connect Google Gmail and Microsoft 365 inboxes directly from the GUI using official vendor OAuth 2.0 PKCE.");
        subtitle.setFont(UiTheme.FONT_SMALL);
        subtitle.setForeground(UiTheme.TEXT_MUTED);

        header.add(title);
        header.add(subtitle);
        add(header, BorderLayout.NORTH);
    }

    private void initCards() {
        JPanel content = new JPanel(new GridLayout(1, 2, 20, 0));
        content.setOpaque(false);

        // 1. Google Gmail Card
        content.add(createGmailCard());

        // 2. Microsoft Outlook / 365 Card
        content.add(createOutlookCard());

        add(content, BorderLayout.CENTER);

        // Bottom Consent and Security Guarantee
        JPanel bottomNotice = UiTheme.createCardPanel();
        bottomNotice.setLayout(new BorderLayout());
        JLabel lblNotice = new JLabel("<html><strong style='color:#38bdf8;'>Security & Privacy Design Guarantee:</strong> " +
                "MailShield connects exclusively via official vendor OAuth 2.0 identity endpoints with <strong>read-only mailbox access</strong> (<code>GmailScopes.GMAIL_READONLY</code> / <code>Mail.Read</code>). " +
                "This application NEVER collects or handles your account passwords, never transmits, modifies, deletes, or forwards emails. All message analysis and SQLite persistence take place locally on this workstation.</html>");
        lblNotice.setFont(UiTheme.FONT_SMALL);
        bottomNotice.add(lblNotice, BorderLayout.CENTER);
        add(bottomNotice, BorderLayout.SOUTH);
    }

    private JPanel createGmailCard() {
        JPanel card = UiTheme.createCardPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));

        JLabel title = new JLabel("Google Gmail API");
        title.setFont(UiTheme.FONT_HEADER);
        title.setForeground(UiTheme.ACCENT_CYAN);

        JLabel desc = new JLabel("<html>Connects via official Google OAuth2 PKCE installed desktop flow. Minimum scope: <code>gmail.readonly</code>.</html>");
        desc.setFont(UiTheme.FONT_SMALL);
        desc.setForeground(UiTheme.TEXT_MUTED);

        lblGmailCredStatus = new JLabel("Credentials: Checking...");
        lblGmailCredStatus.setFont(UiTheme.FONT_SMALL);

        lblGmailStatus = new JLabel("Session: Disconnected");
        lblGmailIdentity = new JLabel("Authorized Mailbox: Not connected");
        lblGmailLastSync = new JLabel("Last Synchronized: Never");

        JPanel btnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        btnBar.setOpaque(false);

        JButton btnConfig = UiTheme.createStyledButton("⚙ Configure", UiTheme.CARD_BG);
        btnConfig.setBorder(BorderFactory.createLineBorder(UiTheme.ACCENT_CYAN, 1));
        btnConfig.addActionListener(e -> showGmailConfigDialog());

        JButton btnConnect = UiTheme.createStyledButton("Connect Gmail", UiTheme.ACCENT_BLUE);
        btnConnect.addActionListener(e -> connectGmail());

        JButton btnSync = UiTheme.createStyledButton("Sync (10 Msgs)", UiTheme.CARD_BG);
        btnSync.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnSync.addActionListener(e -> syncProvider(ProviderType.GMAIL));

        JButton btnDisconnect = UiTheme.createStyledButton("Disconnect", UiTheme.CARD_BG);
        btnDisconnect.setBorder(BorderFactory.createLineBorder(UiTheme.COLOR_CRITICAL, 1));
        btnDisconnect.addActionListener(e -> disconnectProvider(ProviderType.GMAIL));

        btnBar.add(btnConfig);
        btnBar.add(btnConnect);
        btnBar.add(btnSync);
        btnBar.add(btnDisconnect);

        card.add(title);
        card.add(Box.createVerticalStrut(6));
        card.add(desc);
        card.add(Box.createVerticalStrut(12));
        card.add(lblGmailCredStatus);
        card.add(Box.createVerticalStrut(6));
        card.add(lblGmailStatus);
        card.add(Box.createVerticalStrut(6));
        card.add(lblGmailIdentity);
        card.add(Box.createVerticalStrut(6));
        card.add(lblGmailLastSync);
        card.add(Box.createVerticalStrut(18));
        card.add(btnBar);
        card.add(Box.createVerticalGlue());

        return card;
    }

    private JPanel createOutlookCard() {
        JPanel card = UiTheme.createCardPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));

        JLabel title = new JLabel("Microsoft Outlook / 365");
        title.setFont(UiTheme.FONT_HEADER);
        title.setForeground(UiTheme.ACCENT_CYAN);

        JLabel desc = new JLabel("<html>Connects via Microsoft Authentication Library (MSAL) and Microsoft Graph API. Minimum scope: <code>Mail.Read</code>.</html>");
        desc.setFont(UiTheme.FONT_SMALL);
        desc.setForeground(UiTheme.TEXT_MUTED);

        lblOutlookCredStatus = new JLabel("Credentials: Checking...");
        lblOutlookCredStatus.setFont(UiTheme.FONT_SMALL);

        lblOutlookStatus = new JLabel("Session: Disconnected");
        lblOutlookIdentity = new JLabel("Authorized Mailbox: Not connected");
        lblOutlookLastSync = new JLabel("Last Synchronized: Never");

        JPanel btnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        btnBar.setOpaque(false);

        JButton btnConfig = UiTheme.createStyledButton("⚙ Configure", UiTheme.CARD_BG);
        btnConfig.setBorder(BorderFactory.createLineBorder(UiTheme.ACCENT_CYAN, 1));
        btnConfig.addActionListener(e -> showOutlookConfigDialog());

        JButton btnConnect = UiTheme.createStyledButton("Connect Outlook", UiTheme.ACCENT_BLUE);
        btnConnect.addActionListener(e -> connectOutlook());

        JButton btnSync = UiTheme.createStyledButton("Sync (10 Msgs)", UiTheme.CARD_BG);
        btnSync.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnSync.addActionListener(e -> syncProvider(ProviderType.OUTLOOK));

        JButton btnDisconnect = UiTheme.createStyledButton("Disconnect", UiTheme.CARD_BG);
        btnDisconnect.setBorder(BorderFactory.createLineBorder(UiTheme.COLOR_CRITICAL, 1));
        btnDisconnect.addActionListener(e -> disconnectProvider(ProviderType.OUTLOOK));

        btnBar.add(btnConfig);
        btnBar.add(btnConnect);
        btnBar.add(btnSync);
        btnBar.add(btnDisconnect);

        card.add(title);
        card.add(Box.createVerticalStrut(6));
        card.add(desc);
        card.add(Box.createVerticalStrut(12));
        card.add(lblOutlookCredStatus);
        card.add(Box.createVerticalStrut(6));
        card.add(lblOutlookStatus);
        card.add(Box.createVerticalStrut(6));
        card.add(lblOutlookIdentity);
        card.add(Box.createVerticalStrut(6));
        card.add(lblOutlookLastSync);
        card.add(Box.createVerticalStrut(18));
        card.add(btnBar);
        card.add(Box.createVerticalGlue());

        return card;
    }

    /**
     * Modal dialog allowing user to configure Google OAuth credentials directly inside the GUI.
     */
    public void showGmailConfigDialog() {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Configure Google Gmail OAuth 2.0 Credentials", true);
        dialog.setSize(580, 360);
        dialog.setLocationRelativeTo(this);
        dialog.setLayout(new BorderLayout(16, 16));
        dialog.getContentPane().setBackground(UiTheme.BG_DARK);

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(new EmptyBorder(16, 20, 16, 20));
        content.setOpaque(false);

        JLabel info = new JLabel("<html><strong>Configure Google Cloud Credentials (In-App GUI Mode):</strong><br/>" +
                "1. Create a project in Google Cloud Console &rarr; Enable 'Gmail API'.<br/>" +
                "2. Create Credentials &rarr; OAuth client ID &rarr; Desktop Application.<br/>" +
                "3. Paste your Client ID and Client Secret below. Changes save directly to .env.</html>");
        info.setFont(UiTheme.FONT_SMALL);
        info.setForeground(UiTheme.TEXT_MUTED);
        content.add(info);
        content.add(Box.createVerticalStrut(16));

        JPanel form = new JPanel(new GridLayout(3, 2, 10, 10));
        form.setOpaque(false);

        JTextField txtClientId = new JTextField(appConfig.getGmailClientId());
        txtClientId.setFont(UiTheme.FONT_MONO);

        JPasswordField txtSecret = new JPasswordField(appConfig.getGmailClientSecret());
        txtSecret.setFont(UiTheme.FONT_MONO);

        JTextField txtPort = new JTextField(String.valueOf(appConfig.getGmailRedirectPort()));
        txtPort.setFont(UiTheme.FONT_MONO);

        form.add(new JLabel("Google Client ID:"));
        form.add(txtClientId);
        form.add(new JLabel("Google Client Secret:"));
        form.add(txtSecret);
        form.add(new JLabel("Loopback Redirect Port:"));
        form.add(txtPort);

        content.add(form);
        content.add(Box.createVerticalStrut(10));

        JCheckBox chkShowSecret = new JCheckBox("Show Client Secret in Plaintext");
        chkShowSecret.setOpaque(false);
        chkShowSecret.addActionListener(e -> {
            if (chkShowSecret.isSelected()) {
                txtSecret.setEchoChar((char) 0);
            } else {
                txtSecret.setEchoChar('•');
            }
        });
        content.add(chkShowSecret);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        btnPanel.setOpaque(false);

        JButton btnCancel = UiTheme.createStyledButton("Cancel", UiTheme.CARD_BG);
        btnCancel.addActionListener(e -> dialog.dispose());

        JButton btnSave = UiTheme.createStyledButton("Save & Apply Credentials", UiTheme.ACCENT_BLUE);
        btnSave.addActionListener(e -> {
            String cId = txtClientId.getText().trim();
            String cSec = new String(txtSecret.getPassword()).trim();
            int port = 8888;
            try {
                port = Integer.parseInt(txtPort.getText().trim());
            } catch (Exception ignored) {}

            if (cId.isBlank() || cSec.isBlank()) {
                JOptionPane.showMessageDialog(dialog, "Please provide both Client ID and Client Secret.", "Input Required", JOptionPane.WARNING_MESSAGE);
                return;
            }

            try {
                appConfig.saveCredentials(cId, cSec, port,
                        appConfig.getOutlookClientId(), appConfig.getOutlookTenantId(), appConfig.getVirusTotalApiKey());

                EmailProvider p = providers.get(ProviderType.GMAIL);
                if (p instanceof GmailProvider gp) {
                    gp.setCredentials(cId, cSec, port);
                }

                dialog.dispose();
                refreshStatus();

                JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                        "✓ Google Gmail credentials successfully saved & applied!\n\n" +
                        "Client ID: " + (cId.length() > 20 ? cId.substring(0, 15) + "..." + cId.substring(cId.length() - 10) : cId) + "\n" +
                        "Redirect Port: " + port + "\n\n" +
                        "You can now click 'Connect Gmail' to authorize your mailbox in your browser.",
                        "Credentials Saved", JOptionPane.INFORMATION_MESSAGE);

            } catch (Exception ex) {
                JOptionPane.showMessageDialog(dialog, "Failed to save configuration: " + ex.getMessage(), "Save Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        btnPanel.add(btnCancel);
        btnPanel.add(btnSave);

        dialog.add(content, BorderLayout.CENTER);
        dialog.add(btnPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }

    /**
     * Modal dialog allowing user to configure Microsoft Outlook credentials directly inside the GUI.
     */
    public void showOutlookConfigDialog() {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Configure Microsoft 365 / Entra Credentials", true);
        dialog.setSize(560, 320);
        dialog.setLocationRelativeTo(this);
        dialog.setLayout(new BorderLayout(16, 16));
        dialog.getContentPane().setBackground(UiTheme.BG_DARK);

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(new EmptyBorder(16, 20, 16, 20));
        content.setOpaque(false);

        JLabel info = new JLabel("<html><strong>Configure Microsoft Entra ID (In-App GUI Mode):</strong><br/>" +
                "1. Register an Application in Microsoft Entra admin center.<br/>" +
                "2. Supported account types: Personal Microsoft accounts or Any organizational directory.<br/>" +
                "3. API Permissions: Delegated 'Mail.Read'.<br/>" +
                "4. Paste your Application (Client) ID below.</html>");
        info.setFont(UiTheme.FONT_SMALL);
        info.setForeground(UiTheme.TEXT_MUTED);
        content.add(info);
        content.add(Box.createVerticalStrut(16));

        JPanel form = new JPanel(new GridLayout(2, 2, 10, 10));
        form.setOpaque(false);

        JTextField txtClientId = new JTextField(appConfig.getOutlookClientId());
        txtClientId.setFont(UiTheme.FONT_MONO);

        JTextField txtTenantId = new JTextField(appConfig.getOutlookTenantId());
        txtTenantId.setFont(UiTheme.FONT_MONO);

        form.add(new JLabel("Application (Client) ID:"));
        form.add(txtClientId);
        form.add(new JLabel("Directory (Tenant) ID:"));
        form.add(txtTenantId);

        content.add(form);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        btnPanel.setOpaque(false);

        JButton btnCancel = UiTheme.createStyledButton("Cancel", UiTheme.CARD_BG);
        btnCancel.addActionListener(e -> dialog.dispose());

        JButton btnSave = UiTheme.createStyledButton("Save & Apply Credentials", UiTheme.ACCENT_BLUE);
        btnSave.addActionListener(e -> {
            String cId = txtClientId.getText().trim();
            String tId = txtTenantId.getText().trim();
            if (tId.isBlank()) tId = "common";

            if (cId.isBlank()) {
                JOptionPane.showMessageDialog(dialog, "Please enter your Microsoft Application (Client) ID.", "Input Required", JOptionPane.WARNING_MESSAGE);
                return;
            }

            try {
                appConfig.saveCredentials(appConfig.getGmailClientId(), appConfig.getGmailClientSecret(),
                        appConfig.getGmailRedirectPort(), cId, tId, appConfig.getVirusTotalApiKey());

                EmailProvider p = providers.get(ProviderType.OUTLOOK);
                if (p instanceof OutlookProvider op) {
                    op.setCredentials(cId, tId);
                }

                dialog.dispose();
                refreshStatus();

                JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                        "✓ Microsoft Entra credentials successfully saved & applied!\n\n" +
                        "Client ID: " + cId + "\n" +
                        "Tenant ID: " + tId + "\n\n" +
                        "You can now click 'Connect Outlook' to authorize your mailbox.",
                        "Credentials Saved", JOptionPane.INFORMATION_MESSAGE);

            } catch (Exception ex) {
                JOptionPane.showMessageDialog(dialog, "Failed to save configuration: " + ex.getMessage(), "Save Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        btnPanel.add(btnCancel);
        btnPanel.add(btnSave);

        dialog.add(content, BorderLayout.CENTER);
        dialog.add(btnPanel, BorderLayout.SOUTH);
        dialog.setVisible(true);
    }

    private void connectGmail() {
        EmailProvider provider = providers.get(ProviderType.GMAIL);
        if (provider instanceof GmailProvider gp) {
            if (!gp.hasStoredCredentials()) {
                int opt = JOptionPane.showConfirmDialog(this,
                        "Google Client ID & Secret are not yet configured.\n\n" +
                        "Would you like to configure your Google OAuth credentials now?",
                        "Configuration Required", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
                if (opt == JOptionPane.YES_OPTION) {
                    showGmailConfigDialog();
                }
                return;
            }

            // Provide immediate user feedback that authorization is beginning
            lblGmailStatus.setText("Session: Opening Web Browser for OAuth Sign-In...");
            lblGmailStatus.setForeground(UiTheme.ACCENT_CYAN);

            JDialog waitDialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), "Connecting Google Gmail...", false);
            waitDialog.setSize(440, 140);
            waitDialog.setLocationRelativeTo(this);
            JPanel p = new JPanel(new BorderLayout(12, 12));
            p.setBackground(UiTheme.BG_DARK);
            p.setBorder(new EmptyBorder(16, 20, 16, 20));
            JLabel lblMsg = new JLabel("<html><strong>Waiting for Google Sign-In...</strong><br/>Please complete the OAuth consent screen in your web browser.</html>");
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

                        if (success) {
                            JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                                    "✓ Google Gmail Connected Successfully!\n\n" +
                                    "Authorized Mailbox: " + gp.getStatus().getAccountEmail() + "\n" +
                                    "OAuth Status: " + gp.getStatus().getSyncStatus() + "\n" +
                                    "Permissions: Read-Only Email Inspection (gmail.readonly)\n\n" +
                                    "Your inbox is connected. Click 'Sync (10 Msgs)' to ingest and inspect your emails.",
                                    "Google Gmail Connected", JOptionPane.INFORMATION_MESSAGE);
                        } else {
                            String err = gp.getLastErrorMessage();
                            if (err == null || err.isBlank()) err = "Authorization was cancelled or did not complete.";
                            JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                                    "Google Gmail Authorization Did Not Complete:\n\n" +
                                    err + "\n\n" +
                                    "Troubleshooting Checklist:\n" +
                                    "1. Did you grant permissions in the browser window that opened?\n" +
                                    "2. Is 'Gmail API' enabled in your Google Cloud Console project?\n" +
                                    "3. If your OAuth app status is 'Testing', is your email in 'Test Users'?\n" +
                                    "4. Verify your Client ID and Client Secret via the 'Configure' button.",
                                    "Authentication Failed", JOptionPane.ERROR_MESSAGE);
                        }
                    } catch (Exception ex) {
                        refreshStatus();
                        JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                                "Error during OAuth flow: " + ex.getMessage(),
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
            if (!op.hasStoredCredentials()) {
                int opt = JOptionPane.showConfirmDialog(this,
                        "Microsoft Entra Application (Client) ID is not yet configured.\n\n" +
                        "Would you like to configure your Microsoft credentials now?",
                        "Configuration Required", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
                if (opt == JOptionPane.YES_OPTION) {
                    showOutlookConfigDialog();
                }
                return;
            }

            lblOutlookStatus.setText("Session: Initiating Microsoft Entra Device Sign-In...");
            lblOutlookStatus.setForeground(UiTheme.ACCENT_CYAN);

            SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
                @Override
                protected Boolean doInBackground() {
                    return op.authenticate();
                }

                @Override
                protected void done() {
                    try {
                        boolean success = get();
                        refreshStatus();

                        if (success) {
                            JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                                    "✓ Microsoft Outlook / 365 Connected Successfully!\n\n" +
                                    "Authorized Mailbox: " + op.getStatus().getAccountEmail() + "\n" +
                                    "OAuth Status: " + op.getStatus().getSyncStatus() + "\n" +
                                    "Permissions: Read-Only Email Inspection (Mail.Read)\n\n" +
                                    "Your inbox is connected. Click 'Sync (10 Msgs)' to ingest emails.",
                                    "Microsoft 365 Connected", JOptionPane.INFORMATION_MESSAGE);
                        } else {
                            String err = op.getLastErrorMessage();
                            if (err == null || err.isBlank()) err = "Authorization was cancelled or did not complete.";
                            JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                                    "Microsoft Outlook Authorization Did Not Complete:\n\n" +
                                    err + "\n\n" +
                                    "Troubleshooting Checklist:\n" +
                                    "1. Follow the device login prompt instructions printed in console.\n" +
                                    "2. Ensure 'Mail.Read' delegated permission is granted in Microsoft Entra.\n" +
                                    "3. Verify your Client ID in 'Configure' button.",
                                    "Authentication Failed", JOptionPane.ERROR_MESSAGE);
                        }
                    } catch (Exception ex) {
                        refreshStatus();
                        JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                                "Error during Microsoft Entra flow: " + ex.getMessage(),
                                "Authentication Exception", JOptionPane.ERROR_MESSAGE);
                    }
                }
            };
            worker.execute();
        }
    }

    private void disconnectProvider(ProviderType type) {
        EmailProvider p = providers.get(type);
        if (p != null) {
            int opt = JOptionPane.showConfirmDialog(this,
                    "Are you sure you want to disconnect " + type.getTitle() + "?\nStored session tokens will be purged.",
                    "Confirm Disconnect", JOptionPane.YES_NO_OPTION);
            if (opt == JOptionPane.YES_OPTION) {
                p.disconnect();
                refreshStatus();
                JOptionPane.showMessageDialog(this, type.getTitle() + " has been disconnected.", "Disconnected", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    private void syncProvider(ProviderType type) {
        EmailProvider p = providers.get(type);
        if (p == null || !p.getStatus().isConnected()) {
            JOptionPane.showMessageDialog(this,
                    type.getTitle() + " is not authorized. Please connect your account first.",
                    "Sync Unavailable", JOptionPane.WARNING_MESSAGE);
            return;
        }

        SwingWorker<Integer, Void> worker = new SwingWorker<>() {
            @Override
            protected Integer doInBackground() {
                if (monitoringService != null) {
                    monitoringService.setActiveProvider(type);
                    return monitoringService.triggerOnDemandSync(10);
                }
                return 0;
            }

            @Override
            protected void done() {
                try {
                    int count = get();
                    JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                            "✓ Synchronization completed successfully!\n" +
                            "Ingested and analyzed: " + count + " new messages from " + type.getTitle() + ".\n\n" +
                            "Inspect results in 'Overview Dashboard' or 'Investigation Queue'.",
                            "Sync Pass Complete", JOptionPane.INFORMATION_MESSAGE);
                    refreshStatus();
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(ConnectedInboxesPanel.this,
                            "Sync Error: " + ex.getMessage(), "Sync Failed", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }

    public void refreshStatus() {
        EmailProvider gmail = providers.get(ProviderType.GMAIL);
        if (gmail != null) {
            ProviderConnectionStatus st = gmail.getStatus();
            boolean configured = appConfig.isGmailConfigured() || (gmail instanceof GmailProvider gp && gp.hasStoredCredentials());
            if (configured) {
                String cId = appConfig.getGmailClientId();
                String preview = cId.length() > 25 ? cId.substring(0, 12) + "..." + cId.substring(cId.length() - 10) : cId;
                lblGmailCredStatus.setText("Credentials: ✓ Configured in GUI (" + preview + ")");
                lblGmailCredStatus.setForeground(UiTheme.COLOR_LOW);
            } else {
                lblGmailCredStatus.setText("Credentials: ⚠ Not Configured (Click 'Configure')");
                lblGmailCredStatus.setForeground(UiTheme.COLOR_MEDIUM);
            }

            lblGmailStatus.setText("Session: " + (st.isConnected() ? "Connected (Active OAuth Session)" : st.getSyncStatus()));
            lblGmailStatus.setForeground(st.isConnected() ? UiTheme.COLOR_LOW : UiTheme.TEXT_MUTED);
            lblGmailIdentity.setText("Authorized Mailbox: " + (st.getAccountEmail().isBlank() ? "Not connected" : st.getAccountEmail()));
            lblGmailLastSync.setText("Last Synchronized: " + (st.getLastSyncTime() != null ? TIME_FMT.format(st.getLastSyncTime()) : "Never"));
        }

        EmailProvider outlook = providers.get(ProviderType.OUTLOOK);
        if (outlook != null) {
            ProviderConnectionStatus st = outlook.getStatus();
            boolean configured = appConfig.isOutlookConfigured() || (outlook instanceof OutlookProvider op && op.hasStoredCredentials());
            if (configured) {
                String cId = appConfig.getOutlookClientId();
                String preview = cId.length() > 20 ? cId.substring(0, 8) + "..." + cId.substring(cId.length() - 8) : cId;
                lblOutlookCredStatus.setText("Credentials: ✓ Configured in GUI (" + preview + ")");
                lblOutlookCredStatus.setForeground(UiTheme.COLOR_LOW);
            } else {
                lblOutlookCredStatus.setText("Credentials: ⚠ Not Configured (Click 'Configure')");
                lblOutlookCredStatus.setForeground(UiTheme.COLOR_MEDIUM);
            }

            lblOutlookStatus.setText("Session: " + (st.isConnected() ? "Connected (Active Entra Session)" : st.getSyncStatus()));
            lblOutlookStatus.setForeground(st.isConnected() ? UiTheme.COLOR_LOW : UiTheme.TEXT_MUTED);
            lblOutlookIdentity.setText("Authorized Mailbox: " + (st.getAccountEmail().isBlank() ? "Not connected" : st.getAccountEmail()));
            lblOutlookLastSync.setText("Last Synchronized: " + (st.getLastSyncTime() != null ? TIME_FMT.format(st.getLastSyncTime()) : "Never"));
        }
    }
}
