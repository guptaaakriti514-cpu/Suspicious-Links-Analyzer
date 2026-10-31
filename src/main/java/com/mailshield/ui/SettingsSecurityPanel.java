package com.mailshield.ui;

import com.mailshield.config.AppConfig;
import com.mailshield.security.CredentialStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.File;

/**
 * Screen 9: Application Settings, Credentials & Security Configuration.
 * Manage API keys, local token vaults, database file locations, and retention controls.
 */
public class SettingsSecurityPanel extends JPanel {

    private final AppConfig appConfig;
    private final CredentialStore credentialStore;

    private JTextField txtDbPath;
    private JTextField txtGmailClientId;
    private JTextField txtGmailSecret;
    private JTextField txtOutlookClientId;
    private JTextField txtOutlookTenant;
    private JTextField txtVirusTotalKey;

    public SettingsSecurityPanel(AppConfig appConfig, CredentialStore credentialStore) {
        this.appConfig = appConfig;
        this.credentialStore = credentialStore;

        setLayout(new BorderLayout(16, 16));
        setBackground(UiTheme.BG_DARK);
        setBorder(new EmptyBorder(16, 20, 16, 20));

        initHeader();
        initContent();
    }

    private void initHeader() {
        JPanel header = new JPanel(new GridLayout(2, 1, 0, 4));
        header.setOpaque(false);

        JLabel title = new JLabel("System Settings & Security Boundaries");
        title.setFont(UiTheme.FONT_TITLE);

        JLabel subtitle = new JLabel("Configure OAuth credentials, local SQLite paths, credential vault, and retention controls");
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
        mainCard.add(Box.createVerticalStrut(20));

        // Section 2: OAuth Credentials
        JLabel sec2 = new JLabel("2. OAuth 2.0 Client Credentials (.env Configuration)");
        sec2.setFont(UiTheme.FONT_HEADER);
        sec2.setForeground(UiTheme.ACCENT_CYAN);
        mainCard.add(sec2);
        mainCard.add(Box.createVerticalStrut(8));

        JPanel credGrid = new JPanel(new GridLayout(5, 2, 12, 10));
        credGrid.setOpaque(false);

        credGrid.add(new JLabel("Google Gmail Client ID:"));
        txtGmailClientId = new JTextField(appConfig.getGmailClientId());
        credGrid.add(txtGmailClientId);

        credGrid.add(new JLabel("Google Gmail Client Secret:"));
        txtGmailSecret = new JPasswordField(appConfig.getGmailClientSecret().isBlank() ? "" : "********");
        credGrid.add(txtGmailSecret);

        credGrid.add(new JLabel("Microsoft Entra Client ID:"));
        txtOutlookClientId = new JTextField(appConfig.getOutlookClientId());
        credGrid.add(txtOutlookClientId);

        credGrid.add(new JLabel("Microsoft Entra Tenant ID:"));
        txtOutlookTenant = new JTextField(appConfig.getOutlookTenantId());
        credGrid.add(txtOutlookTenant);

        credGrid.add(new JLabel("VirusTotal API Key (Optional):"));
        txtVirusTotalKey = new JPasswordField(appConfig.getVirusTotalApiKey().isBlank() ? "" : "********");
        credGrid.add(txtVirusTotalKey);

        mainCard.add(credGrid);
        mainCard.add(Box.createVerticalStrut(24));

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

    private void purgeTokens() {
        int opt = JOptionPane.showConfirmDialog(this,
                "Are you sure you want to purge all cached OAuth tokens?\nYou will need to re-authenticate when syncing inboxes.",
                "Purge Tokens", JOptionPane.YES_NO_OPTION);

        if (opt == JOptionPane.YES_OPTION) {
            File tokensDir = new File(appConfig.getDataDir(), "tokens");
            if (tokensDir.exists()) {
                deleteDir(tokensDir);
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

