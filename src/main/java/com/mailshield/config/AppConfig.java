package com.mailshield.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

/**
 * Centralized application configuration.
 * Reads environment variables first, falling back to a local .env file or safe defaults.
 * Supports dynamic GUI runtime updates and automatic persistence back to .env.
 */
public final class AppConfig {

    private static final AppConfig INSTANCE = new AppConfig();

    private final Properties envProps = new Properties();
    private String dataDir;
    private String dbPath;
    private String gmailClientId;
    private String gmailClientSecret;
    private int gmailRedirectPort;
    private String outlookClientId;
    private String outlookTenantId;
    private String virusTotalApiKey;
    private String abuseIpDbApiKey;
    private int pollIntervalSeconds;
    private int maxMessagesPerPoll;
    private boolean autoAnalyze;

    private AppConfig() {
        reload();

        // Ensure data directory exists
        File dir = new File(this.dataDir);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }

    public static AppConfig getInstance() {
        return INSTANCE;
    }

    public synchronized void reload() {
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

    /**
     * Persists updated credentials into .env and updates runtime fields immediately.
     */
    public synchronized void saveCredentials(String gmailClientId,
                                             String gmailClientSecret,
                                             int gmailRedirectPort,
                                             String outlookClientId,
                                             String outlookTenantId,
                                             String virusTotalApiKey) throws IOException {

        this.gmailClientId = gmailClientId != null ? gmailClientId.trim() : "";
        this.gmailClientSecret = gmailClientSecret != null ? gmailClientSecret.trim() : "";
        this.gmailRedirectPort = gmailRedirectPort > 0 ? gmailRedirectPort : 8888;
        this.outlookClientId = outlookClientId != null ? outlookClientId.trim() : "";
        this.outlookTenantId = outlookTenantId != null ? outlookTenantId.trim() : "common";
        this.virusTotalApiKey = virusTotalApiKey != null ? virusTotalApiKey.trim() : "";

        // Update properties
        envProps.setProperty("MAILSHIELD_GMAIL_CLIENT_ID", this.gmailClientId);
        envProps.setProperty("MAILSHIELD_GMAIL_CLIENT_SECRET", this.gmailClientSecret);
        envProps.setProperty("MAILSHIELD_GMAIL_REDIRECT_PORT", String.valueOf(this.gmailRedirectPort));
        envProps.setProperty("MAILSHIELD_OUTLOOK_CLIENT_ID", this.outlookClientId);
        envProps.setProperty("MAILSHIELD_OUTLOOK_TENANT_ID", this.outlookTenantId);
        envProps.setProperty("MAILSHIELD_VIRUSTOTAL_API_KEY", this.virusTotalApiKey);

        // Save back to .env cleanly
        File dotEnv = new File(".env");
        Map<String, String> currentMap = new LinkedHashMap<>();
        if (dotEnv.exists()) {
            List<String> lines = Files.readAllLines(dotEnv.toPath(), StandardCharsets.UTF_8);
            for (String line : lines) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty() && !trimmed.startsWith("#") && trimmed.contains("=")) {
                    int eq = trimmed.indexOf('=');
                    String k = trimmed.substring(0, eq).trim();
                    String v = trimmed.substring(eq + 1).trim();
                    currentMap.put(k, v);
                }
            }
        }

        currentMap.put("MAILSHIELD_GMAIL_CLIENT_ID", this.gmailClientId);
        currentMap.put("MAILSHIELD_GMAIL_CLIENT_SECRET", this.gmailClientSecret);
        currentMap.put("MAILSHIELD_GMAIL_REDIRECT_PORT", String.valueOf(this.gmailRedirectPort));
        currentMap.put("MAILSHIELD_OUTLOOK_CLIENT_ID", this.outlookClientId);
        currentMap.put("MAILSHIELD_OUTLOOK_TENANT_ID", this.outlookTenantId);
        currentMap.put("MAILSHIELD_VIRUSTOTAL_API_KEY", this.virusTotalApiKey);
        if (!currentMap.containsKey("MAILSHIELD_DATA_DIR")) currentMap.put("MAILSHIELD_DATA_DIR", this.dataDir);
        if (!currentMap.containsKey("MAILSHIELD_DB_PATH")) currentMap.put("MAILSHIELD_DB_PATH", this.dbPath);
        if (!currentMap.containsKey("MAILSHIELD_POLL_INTERVAL_SECONDS")) currentMap.put("MAILSHIELD_POLL_INTERVAL_SECONDS", String.valueOf(this.pollIntervalSeconds));
        if (!currentMap.containsKey("MAILSHIELD_MAX_MESSAGES_PER_POLL")) currentMap.put("MAILSHIELD_MAX_MESSAGES_PER_POLL", String.valueOf(this.maxMessagesPerPoll));
        if (!currentMap.containsKey("MAILSHIELD_AUTO_ANALYZE")) currentMap.put("MAILSHIELD_AUTO_ANALYZE", String.valueOf(this.autoAnalyze));

        StringBuilder sb = new StringBuilder();
        sb.append("# MailShield Configuration File (Managed via GUI & .env)\n");
        sb.append("# Updated: ").append(new Date()).append("\n\n");
        for (Map.Entry<String, String> entry : currentMap.entrySet()) {
            sb.append(entry.getKey()).append("=").append(entry.getValue()).append("\n");
        }

        Files.writeString(dotEnv.toPath(), sb.toString(), StandardCharsets.UTF_8);
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
