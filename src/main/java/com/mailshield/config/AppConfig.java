package com.mailshield.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

/**
 * Centralized application configuration.
 * Reads environment variables first, falling back to a local .env file or safe defaults.
 */
public final class AppConfig {

    private static final AppConfig INSTANCE = new AppConfig();

    private final Properties envProps = new Properties();
    private final String dataDir;
    private final String dbPath;
    private final String gmailClientId;
    private final String gmailClientSecret;
    private final int gmailRedirectPort;
    private final String outlookClientId;
    private final String outlookTenantId;
    private final String virusTotalApiKey;
    private final String abuseIpDbApiKey;
    private final int pollIntervalSeconds;
    private final int maxMessagesPerPoll;
    private final boolean autoAnalyze;

    private AppConfig() {
        loadDotEnv();

        this.dataDir = getVal("MAILSHIELD_DATA_DIR", "data");
        this.dbPath = getVal("MAILSHIELD_DB_PATH", dataDir + File.separator + "mailshield.db");
        this.gmailClientId = getVal("MAILSHIELD_GMAIL_CLIENT_ID", "");
        this.gmailClientSecret = getVal("MAILSHIELD_GMAIL_CLIENT_SECRET", "");
        this.gmailRedirectPort = Integer.parseInt(getVal("MAILSHIELD_GMAIL_REDIRECT_PORT", "8888"));
        this.outlookClientId = getVal("MAILSHIELD_OUTLOOK_CLIENT_ID", "");
        this.outlookTenantId = getVal("MAILSHIELD_OUTLOOK_TENANT_ID", "common");
        this.virusTotalApiKey = getVal("MAILSHIELD_VIRUSTOTAL_API_KEY", "");
        this.abuseIpDbApiKey = getVal("MAILSHIELD_ABUSEIPDB_API_KEY", "");
        this.pollIntervalSeconds = Integer.parseInt(getVal("MAILSHIELD_POLL_INTERVAL_SECONDS", "60"));
        this.maxMessagesPerPoll = Integer.parseInt(getVal("MAILSHIELD_MAX_MESSAGES_PER_POLL", "25"));
        this.autoAnalyze = Boolean.parseBoolean(getVal("MAILSHIELD_AUTO_ANALYZE", "true"));

        // Ensure data directory exists
        File dir = new File(this.dataDir);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }

    public static AppConfig getInstance() {
        return INSTANCE;
    }

    private void loadDotEnv() {
        File dotEnv = new File(".env");
        if (dotEnv.exists() && dotEnv.isFile()) {
            try (FileInputStream fis = new FileInputStream(dotEnv)) {
                envProps.load(fis);
            } catch (IOException ignored) {}
        }
    }

    private String getVal(String key, String defaultValue) {
        String sysEnv = System.getenv(key);
        if (sysEnv != null && !sysEnv.trim().isEmpty()) {
            return sysEnv.trim();
        }
        String propVal = envProps.getProperty(key);
        if (propVal != null && !propVal.trim().isEmpty()) {
            return propVal.trim();
        }
        return defaultValue;
    }

    public String getDataDir() { return dataDir; }
    public String getDbPath() { return dbPath; }
    public String getGmailClientId() { return gmailClientId; }
    public String getGmailClientSecret() { return gmailClientSecret; }
    public int getGmailRedirectPort() { return gmailRedirectPort; }
    public String getOutlookClientId() { return outlookClientId; }
    public String getOutlookTenantId() { return outlookTenantId; }
    public String getVirusTotalApiKey() { return virusTotalApiKey; }
    public String getAbuseIpDbApiKey() { return abuseIpDbApiKey; }
    public int getPollIntervalSeconds() { return pollIntervalSeconds; }
    public int getMaxMessagesPerPoll() { return maxMessagesPerPoll; }
    public boolean isAutoAnalyze() { return autoAnalyze; }

    public boolean isGmailConfigured() {
        return gmailClientId != null && !gmailClientId.isBlank() && !gmailClientId.contains("your-google");
    }

    public boolean isOutlookConfigured() {
        return outlookClientId != null && !outlookClientId.isBlank() && !outlookClientId.contains("your-microsoft");
    }

    public boolean isVirusTotalConfigured() {
        return virusTotalApiKey != null && !virusTotalApiKey.isBlank();
    }
}

