package com.mailshield.ui;

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
 */
public class ConnectedInboxesPanel extends JPanel {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault());

    private final Map<ProviderType, EmailProvider> providers;
    private final MonitoringService monitoringService;

    private JLabel lblGmailStatus;
    private JLabel lblGmailIdentity;
    private JLabel lblGmailLastSync;

    private JLabel lblOutlookStatus;
    private JLabel lblOutlookIdentity;
    private JLabel lblOutlookLastSync;

    public ConnectedInboxesPanel(Map<ProviderType, EmailProvider> providers, MonitoringService monitoringService) {
        this.providers = providers;
        this.monitoringService = monitoringService;

        setLayout(new BorderLayout(16, 20));
        setBackground(UiTheme.BG_DARK);
        setBorder(new EmptyBorder(20, 24, 20, 24));

        initHeader();
        initCards();
        refreshStatus();
    }

    private void initHeader() {
        JPanel header = new JPanel(new GridLayout(2, 1, 0, 4));
        header.setOpaque(false);

        JLabel title = new JLabel("Authorized Mailbox Integrations");
        title.setFont(UiTheme.FONT_TITLE);

        JLabel subtitle = new JLabel("Connect enterprise and personal inboxes using official OAuth 2.0 PKCE and Microsoft Entra Delegated flows.");
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

        lblGmailStatus = new JLabel("Status: Checking...");
        lblGmailIdentity = new JLabel("Authorized Mailbox: Not connected");
        lblGmailLastSync = new JLabel("Last Synchronized: Never");

        JPanel btnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        btnBar.setOpaque(false);

        JButton btnConnect = UiTheme.createStyledButton("Connect Gmail", UiTheme.ACCENT_BLUE);
        btnConnect.addActionListener(e -> connectGmail());

        JButton btnSync = UiTheme.createStyledButton("Sync (10 Msgs)", UiTheme.CARD_BG);
        btnSync.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnSync.addActionListener(e -> syncProvider(ProviderType.GMAIL));

        JButton btnDisconnect = UiTheme.createStyledButton("Disconnect", UiTheme.CARD_BG);
        btnDisconnect.setBorder(BorderFactory.createLineBorder(UiTheme.COLOR_CRITICAL, 1));
        btnDisconnect.addActionListener(e -> disconnectProvider(ProviderType.GMAIL));

        btnBar.add(btnConnect);
        btnBar.add(btnSync);
        btnBar.add(btnDisconnect);

        card.add(title);
        card.add(Box.createVerticalStrut(6));
        card.add(desc);
        card.add(Box.createVerticalStrut(16));
        card.add(lblGmailStatus);
        card.add(Box.createVerticalStrut(6));
        card.add(lblGmailIdentity);
        card.add(Box.createVerticalStrut(6));
        card.add(lblGmailLastSync);
        card.add(Box.createVerticalStrut(20));
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

        lblOutlookStatus = new JLabel("Status: Checking...");
        lblOutlookIdentity = new JLabel("Authorized Mailbox: Not connected");
        lblOutlookLastSync = new JLabel("Last Synchronized: Never");

        JPanel btnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        btnBar.setOpaque(false);

        JButton btnConnect = UiTheme.createStyledButton("Connect Outlook", UiTheme.ACCENT_BLUE);
        btnConnect.addActionListener(e -> connectOutlook());

        JButton btnSync = UiTheme.createStyledButton("Sync (10 Msgs)", UiTheme.CARD_BG);
        btnSync.setBorder(BorderFactory.createLineBorder(UiTheme.BORDER_COLOR, 1));
        btnSync.addActionListener(e -> syncProvider(ProviderType.OUTLOOK));

        JButton btnDisconnect = UiTheme.createStyledButton("Disconnect", UiTheme.CARD_BG);
        btnDisconnect.setBorder(BorderFactory.createLineBorder(UiTheme.COLOR_CRITICAL, 1));
        btnDisconnect.addActionListener(e -> disconnectProvider(ProviderType.OUTLOOK));

        btnBar.add(btnConnect);
        btnBar.add(btnSync);
        btnBar.add(btnDisconnect);

        card.add(title);
        card.add(Box.createVerticalStrut(6));
        card.add(desc);
        card.add(Box.createVerticalStrut(16));
        card.add(lblOutlookStatus);
        card.add(Box.createVerticalStrut(6));
        card.add(lblOutlookIdentity);
        card.add(Box.createVerticalStrut(6));
        card.add(lblOutlookLastSync);
        card.add(Box.createVerticalStrut(20));
        card.add(btnBar);
        card.add(Box.createVerticalGlue());

        return card;
    }

    private void connectGmail() {
        EmailProvider provider = providers.get(ProviderType.GMAIL);
        if (provider instanceof GmailProvider gp) {
            if (!gp.hasStoredCredentials()) {
                JOptionPane.showMessageDialog(this,
                        "Google Client ID & Secret are not configured in your .env or environment.\n\n" +
                        "1. Create a project in Google Cloud Console.\n" +
                        "2. Enable Gmail API.\n" +
                        "3. Create OAuth 2.0 Client ID (Desktop Application).\n" +
                        "4. Add Client ID & Secret in .env or Settings tab.",
                        "Configuration Required", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
                @Override
                protected Boolean doInBackground() {
                    return gp.authenticate();
                }

                @Override
                protected void done() {
                    refreshStatus();
                }
            };
            worker.execute();
        }
    }

    private void connectOutlook() {
        EmailProvider provider = providers.get(ProviderType.OUTLOOK);
        if (provider instanceof OutlookProvider op) {
            if (!op.hasStoredCredentials()) {
                JOptionPane.showMessageDialog(this,
                        "Microsoft Entra Application (Client) ID is not configured in your .env.\n\n" +
                        "1. Register an application in Microsoft Entra admin center.\n" +
                        "2. Select Mobile and desktop applications.\n" +
                        "3. Add delegated permission: Mail.Read.\n" +
                        "4. Add Client ID in .env or Settings tab.",
                        "Configuration Required", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
                @Override
                protected Boolean doInBackground() {
                    return op.authenticate();
                }

                @Override
                protected void done() {
                    refreshStatus();
                }
            };
            worker.execute();
        }
    }

    private void disconnectProvider(ProviderType type) {
        EmailProvider p = providers.get(type);
        if (p != null) {
            p.disconnect();
            refreshStatus();
        }
    }

    private void syncProvider(ProviderType type) {
        EmailProvider p = providers.get(type);
        if (p == null || !p.getStatus().isConnected()) {
            JOptionPane.showMessageDialog(this, "Provider is not authorized. Please connect first.", "Sync Unavailable", JOptionPane.WARNING_MESSAGE);
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
                            "Synchronization completed successfully!\nIngested and analyzed: " + count + " new messages.",
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
            lblGmailStatus.setText("Status: " + (st.isConnected() ? "Connected (Active OAuth Session)" : st.getSyncStatus()));
            lblGmailStatus.setForeground(st.isConnected() ? UiTheme.COLOR_LOW : UiTheme.COLOR_HIGH);
            lblGmailIdentity.setText("Authorized Mailbox: " + (st.getAccountEmail().isBlank() ? "None" : st.getAccountEmail()));
            lblGmailLastSync.setText("Last Synchronized: " + (st.getLastSyncTime() != null ? TIME_FMT.format(st.getLastSyncTime()) : "Never"));
        }

        EmailProvider outlook = providers.get(ProviderType.OUTLOOK);
        if (outlook != null) {
            ProviderConnectionStatus st = outlook.getStatus();
            lblOutlookStatus.setText("Status: " + (st.isConnected() ? "Connected (Active Entra Session)" : st.getSyncStatus()));
            lblOutlookStatus.setForeground(st.isConnected() ? UiTheme.COLOR_LOW : UiTheme.COLOR_HIGH);
            lblOutlookIdentity.setText("Authorized Mailbox: " + (st.getAccountEmail().isBlank() ? "None" : st.getAccountEmail()));
            lblOutlookLastSync.setText("Last Synchronized: " + (st.getLastSyncTime() != null ? TIME_FMT.format(st.getLastSyncTime()) : "Never"));
        }
    }
}

