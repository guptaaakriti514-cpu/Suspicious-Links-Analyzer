package com.mailshield.model;

public enum ProviderType {
    MANUAL_PASTE("Manual Paste", "User pasted raw email headers or body"),
    EML_FILE("EML File Import", "Locally imported RFC 5322 .eml file"),
    GMAIL("Google Gmail API", "Connected via Google OAuth2 PKCE"),
    OUTLOOK("Microsoft Outlook / 365", "Connected via Microsoft Entra Graph API"),
    DEMO_FIXTURE("Synthetic Demo Fixture", "Offline sample scenario for academic viva");

    private final String title;
    private final String description;

    ProviderType(String title, String description) {
        this.title = title;
        this.description = description;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }
}

