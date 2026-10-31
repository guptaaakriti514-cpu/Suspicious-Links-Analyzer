package com.mailshield.ui;

import com.mailshield.config.AppConfig;
import com.mailshield.model.ProviderType;
import com.mailshield.providers.EmailProvider;
import com.mailshield.providers.GmailProvider;
import com.mailshield.providers.OutlookProvider;
import com.mailshield.security.CredentialStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;
import java.util.Map;

/**
 * Screen 9: Application Settings, Credentials & Security Configuration.
 * Manage API keys, local token vaults, database file locations, and retention controls.
 * Supports direct GUI configuration, persistent saving to .env, and instant live updates.
 */
public class SettingsSecurityPanel extends JPanel {

    private final AppConfig appConfig;
    private final CredentialStore credentialStore;
    private final Map<ProviderType, EmailProvider> providers;
    private final Runnable onConfigChanged;

    private JTextField txtDbPath;
    private JTextField txtGmailClientId;
    private JPasswordField txtGmailSecret;
    private JTextField txtGmailPort;
    private JTextField txtOutlookClientId;
    private JTextField txtOutlookTenant;
    private JPasswordField txtVirusTotalKey;

    public SettingsSecurityPanel(AppConfig appConfig,
                                 CredentialStore credentialStore,
                                 Map<ProviderType, EmailProvider> providers,
                                 Runnable onConfigChanged) {
        this.appConfig = appConfig;
        this.credentialStore = credentialStore;
        this.providers = providers;
        this.onConfigChanged = onConfigChanged;

        setLayout(new BorderLayout(16, 16));
        setBackground(UiTheme.BG_DARK);
        setBorder(new EmptyBorder(16, 20, 16, 20));

        initHeader();
        initContent();
    }

    public SettingsSecurityPanel(AppConfig appConfig, CredentialStore credentialStore) {
        this(appConfig, credentialStore, null, null);
    }

    private void initHeader() {
        JPanel header = new JPanel(new GridLayout(2, 1, 0, 4));
        header.setOpaque(false);

        JLabel title = new JLabel("System Settings & Security Boundaries");
        title.setFont(UiTheme.FONT_TITLE);

        JLabel subtitle = new JLabel("Configure OAuth credentials, local SQLite paths, credential vault, and retention controls directly in GUI");
        subtitle.setFont(UiTheme.FONT_SMALL);
        subtitle.setForeground(UiTheme.TEXT_MUTED);

        header.add(title);
        header.add(subtitle);
        add(header, BorderLayout.NORTH);
    }

    private void initContent() {
        JPanel mainCard = UiTheme.createCardPanel();
        mainCard.setLayout(new BoxLayout(mainCard, BoxLayout.Y_AXIS));

        // Section 1: Storage
        JLabel sec1 = new JLabel("1. Local Database & Forensic Storage");
        sec1.setFont(UiTheme.FONT_HEADER);
        sec1.setForeground(UiTheme.ACCENT_CYAN);
        mainCard.add(sec1);
        mainCard.add(Box.createVerticalStrut(8));

        JPanel dbRow = new JPanel(new BorderLayout(10, 0));
        dbRow.setOpaque(false);
        dbRow.add(new JLabel("SQLite DB Path:   "), BorderLayout.WEST);
        txtDbPath = new JTextField(appConfig.getDbPath());
        txtDbPath.setEditable(false);
        txtDbPath.setFont(UiTheme.FONT_MONO);
        dbRow.add(txtDbPath, BorderLayout.CENTER);
        mainCard.add(dbRow);
        mainCard.add(Box.createVerticalStrut(18));

        // Section 2: OAuth Credentials
        JLabel sec2 = new JLabel("2. OAuth 2.0 & API Credentials (GUI Configuration)");
        sec2.setFont(UiTheme.FONT_HEADER);
        sec2.setForeground(UiTheme.ACCENT_CYAN);
        mainCard.add(sec2);
        mainCard.add(Box.createVerticalStrut(8));

        JPanel credGrid = new JPanel(new GridLayout(6, 2, 12, 10));
        credGrid.setOpaque(false);

        credGrid.add(new JLabel("Google Gmail Client ID:"));
        txtGmailClientId = new JTextField(appConfig.getGmailClientId());
        txtGmailClientId.setFont(UiTheme.FONT_MONO);
        credGrid.add(txtGmailClientId);

        credGrid.add(new JLabel("Google Gmail Client Secret:"));
        txtGmailSecret = new JPasswordField(appConfig.getGmailClientSecret());
        txtGmailSecret.setFont(UiTheme.FONT_MONO);
        credGrid.add(txtGmailSecret);

        credGrid.add(new JLabel("Google Redirect Port:"));
        txtGmailPort = new JTextField(String.valueOf(appConfig.getGmailRedirectPort()));
        txtGmailPort.setFont(UiTheme.FONT_MONO);
        credGrid.add(txtGmailPort);

        credGrid.add(new JLabel("Microsoft Entra Client ID:"));
        txtOutlookClientId = new JTextField(appConfig.getOutlookClientId());
        txtOutlookClientId.setFont(UiTheme.FONT_MONO);
        credGrid.add(txtOutlookClientId);

        credGrid.add(new JLabel("Microsoft Entra Tenant ID:"));
        txtOutlookTenant = new JTextField(appConfig.getOutlookTenantId());
        txtOutlookTenant.setFont(UiTheme.FONT_MONO);
        credGrid.add(txtOutlookTenant);

        credGrid.add(new JLabel("VirusTotal API Key (Optional):"));
        txtVirusTotalKey = new JPasswordField(appConfig.getVirusTotalApiKey());
        txtVirusTotalKey.setFont(UiTheme.FONT_MONO);
        credGrid.add(txtVirusTotalKey);

        mainCard.add(credGrid);
        mainCard.add(Box.createVerticalStrut(10));

        JPanel optRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        optRow.setOpaque(false);

        JCheckBox chkShowSecrets = new JCheckBox("Show Secrets in Plaintext");
        chkShowSecrets.setOpaque(false);
        chkShowSecrets.addActionListener(e -> {
            char echo = chkShowSecrets.isSelected() ? (char) 0 : '•';
            txtGmailSecret.setEchoChar(echo);
            txtVirusTotalKey.setEchoChar(echo);
        });
        optRow.add(chkShowSecrets);

        JButton btnSaveSettings = UiTheme.createStyledButton("💾 Save Configuration to .env", UiTheme.ACCENT_BLUE);
        btnSaveSettings.setPreferredSize(new Dimension(240, 32));
        btnSaveSettings.addActionListener(e -> saveSettings());
        optRow.add(btnSaveSettings);

        mainCard.add(optRow);
        mainCard.add(Box.createVerticalStrut(22));

        // Section 3: Privacy & Token Purging
        JLabel sec3 = new JLabel("3. Privacy Controls & Token Vault Purging");
        sec3.setFont(UiTheme.FONT_HEADER);
        sec3.setForeground(UiTheme.ACCENT_CYAN);
        mainCard.add(sec3);
        mainCard.add(Box.createVerticalStrut(8));

        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        actionRow.setOpaque(false);

        JButton btnPurgeTokens = UiTheme.createStyledButton("Purge Local OAuth Tokens", UiTheme.CARD_BG);
        btnPurgeTokens.setBorder(BorderFactory.createLineBorder(UiTheme.COLOR_CRITICAL, 1));
        btnPurgeTokens.addActionListener(e -> purgeTokens());

        actionRow.add(btnPurgeTokens);
        mainCard.add(actionRow);
        mainCard.add(Box.createVerticalGlue());

        add(mainCard, BorderLayout.CENTER);
    }

    private void saveSettings() {
        String gId = txtGmailClientId.getText().trim();
        String gSec = new String(txtGmailSecret.getPassword()).trim();
        int gPort = 8888;
        try {
            gPort = Integer.parseInt(txtGmailPort.getText().trim());
        } catch (Exception ignored) {}

        String oId = txtOutlookClientId.getText().trim();
        String oTenant = txtOutlookTenant.getText().trim();
        if (oTenant.isBlank()) oTenant = "common";

        String vtKey = new String(txtVirusTotalKey.getPassword()).trim();

        try {
            appConfig.saveCredentials(gId, gSec, gPort, oId, oTenant, vtKey);

            // Update live provider instances
            if (providers != null) {
                EmailProvider gp = providers.get(ProviderType.GMAIL);
                if (gp instanceof GmailProvider gProvider) {
                    gProvider.setCredentials(gId, gSec, gPort);
                }

                EmailProvider op = providers.get(ProviderType.OUTLOOK);
                if (op instanceof OutlookProvider oProvider) {
                    oProvider.setCredentials(oId, oTenant);
                }
            }

            if (onConfigChanged != null) {
                onConfigChanged.run();
            }

            JOptionPane.showMessageDialog(this,
                    "✓ Configuration Successfully Saved!\n\n" +
                    "• Credentials written to local .env\n" +
                    "• Active provider instances updated in memory\n\n" +
                    "You can now connect your accounts in 'Connected Inboxes'.",
                    "Settings Applied", JOptionPane.INFORMATION_MESSAGE);

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Failed to save configuration: " + ex.getMessage(),
                    "Save Failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void purgeTokens() {
        int opt = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to purge all cached OAuth tokens?\nYou will need to re-authenticate when syncing inboxes.",
                "Purge Tokens", JOptionPane.YES_NO_OPTION);

        if (opt == JOptionPane.YES_OPTION) {
            File tokensDir = new File(appConfig.getDataDir(), "tokens");
            if (tokensDir.exists()) {
                deleteDir(tokensDir);
            }
            if (providers != null) {
                EmailProvider gp = providers.get(ProviderType.GMAIL);
                if (gp != null) gp.disconnect();
                EmailProvider op = providers.get(ProviderType.OUTLOOK);
                if (op != null) op.disconnect();
            }
            if (onConfigChanged != null) {
                onConfigChanged.run();
            }
            JOptionPane.showMessageDialog(this, "Local OAuth tokens purged successfully.", "Purged", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void deleteDir(File dir) {
        File[] files = dir.listFiles();
        if (files != null) {
            for (File f : files) {
                if (f.isDirectory()) deleteDir(f);
                else f.delete();
            }
        }
    }
}
