package com.mailshield.providers;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.GmailScopes;
import com.google.api.services.gmail.model.ListMessagesResponse;
import com.google.api.services.gmail.model.Message;
import com.mailshield.config.AppConfig;
import com.mailshield.ingestion.EmailParser;
import com.mailshield.model.EmailMessage;
import com.mailshield.model.ProviderConnectionStatus;
import com.mailshield.model.ProviderType;
import com.mailshield.storage.CaseRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.StringReader;
import java.time.Instant;
import java.util.*;

/**
 * Official Google Gmail API integration using OAuth2 PKCE Desktop Loopback.
 * Requires read-only mailbox permissions (GmailScopes.GMAIL_READONLY).
 * Never collects or handles user passwords.
 */
public class GoogleGmailProvider implements GmailProvider {

    private static final Logger log = LoggerFactory.getLogger(GoogleGmailProvider.class);
    private static final String APPLICATION_NAME = "MailShield Threat Detection Platform";
    private static final List<String> SCOPES = Collections.singletonList(GmailScopes.GMAIL_READONLY);

    private final EmailParser emailParser;
    private final CaseRepository caseRepository;
    private final AppConfig appConfig;

    private String clientId;
    private String clientSecret;
    private int redirectPort;
    private Gmail gmailService;
    private ProviderConnectionStatus currentStatus;
    private String lastErrorMessage;

    public GoogleGmailProvider(EmailParser emailParser, CaseRepository caseRepository, AppConfig appConfig) {
        this.emailParser = emailParser;
        this.caseRepository = caseRepository;
        this.appConfig = appConfig;
        this.clientId = appConfig.getGmailClientId();
        this.clientSecret = appConfig.getGmailClientSecret();
        this.redirectPort = appConfig.getGmailRedirectPort();
        updateStatus();
    }

    private void updateStatus() {
        if (!hasStoredCredentials()) {
            this.currentStatus = ProviderConnectionStatus.notConfigured(ProviderType.GMAIL);
        } else if (gmailService == null) {
            this.currentStatus = new ProviderConnectionStatus(
                    ProviderType.GMAIL, false, "Ready to Connect",
                    null, "Credentials Configured (Awaiting Sign-In)", "", SCOPES, true
            );
        }
    }

    @Override
    public ProviderType getProviderType() {
        return ProviderType.GMAIL;
    }

    @Override
    public ProviderConnectionStatus getStatus() {
        return currentStatus;
    }

    @Override
    public String getLastErrorMessage() {
        return lastErrorMessage != null ? lastErrorMessage : currentStatus.getErrorMessage();
    }

    @Override
    public void setCredentials(String clientId, String clientSecret, int redirectPort) {
        this.clientId = clientId != null ? clientId.trim() : "";
        this.clientSecret = clientSecret != null ? clientSecret.trim() : "";
        this.redirectPort = redirectPort > 0 ? redirectPort : 8888;
        this.lastErrorMessage = null;
        updateStatus();
    }

    @Override
    public boolean hasStoredCredentials() {
        return clientId != null && !clientId.isBlank() && !clientId.contains("your-google")
                && clientSecret != null && !clientSecret.isBlank();
    }

    @Override
    public boolean testConnection() {
        if (!hasStoredCredentials() || gmailService == null) return false;
        try {
            gmailService.users().getProfile("me").execute();
            return true;
        } catch (Exception e) {
            log.warn("Gmail connection test failed: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public boolean authenticate() {
        this.lastErrorMessage = null;
        if (!hasStoredCredentials()) {
            this.lastErrorMessage = "Client ID or Client Secret is missing. Please configure credentials in the GUI first.";
            this.currentStatus = ProviderConnectionStatus.notConfigured(ProviderType.GMAIL);
            return false;
        }

        try {
            NetHttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
            GsonFactory jsonFactory = GsonFactory.getDefaultInstance();

            String clientSecretsJson = String.format(
                    "{\"installed\":{\"client_id\":\"%s\",\"client_secret\":\"%s\",\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\"token_uri\":\"https://oauth2.googleapis.com/token\"}}",
                    clientId, clientSecret
            );

            GoogleClientSecrets secrets = GoogleClientSecrets.load(jsonFactory, new StringReader(clientSecretsJson));
            File tokensDirectory = new File(appConfig.getDataDir(), "tokens/gmail");
            if (!tokensDirectory.exists()) tokensDirectory.mkdirs();

            GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                    httpTransport, jsonFactory, secrets, SCOPES)
                    .setDataStoreFactory(new FileDataStoreFactory(tokensDirectory))
                    .setAccessType("offline")
                    .build();

            Credential credential;
            int preferredPort = (redirectPort > 0 && isPortAvailable(redirectPort)) ? redirectPort : -1;
            try {
                LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(preferredPort).build();
                credential = new AuthorizationCodeInstalledApp(flow, receiver).authorize("user");
            } catch (Exception e) {
                if (preferredPort != -1 && (e instanceof java.net.BindException || (e.getMessage() != null && e.getMessage().contains("already in use")))) {
                    log.warn("Port {} in use or in TIME_WAIT state, retrying with dynamic open port (-1)...", preferredPort);
                    LocalServerReceiver dynamicReceiver = new LocalServerReceiver.Builder().setPort(-1).build();
                    credential = new AuthorizationCodeInstalledApp(flow, dynamicReceiver).authorize("user");
                } else {
                    throw e;
                }
            }

            this.gmailService = new Gmail.Builder(httpTransport, jsonFactory, credential)
                    .setApplicationName(APPLICATION_NAME)
                    .build();

            var profile = gmailService.users().getProfile("me").execute();
            String userEmail = profile.getEmailAddress();

            this.currentStatus = new ProviderConnectionStatus(
                    ProviderType.GMAIL, true, userEmail, Instant.now(),
                    "Connected (Authorized via Google OAuth2)", "", SCOPES, true
            );
            log.info("Gmail OAuth2 successfully authorized for mailbox: {}", userEmail);
            return true;

        } catch (Exception e) {
            this.lastErrorMessage = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            log.error("Gmail OAuth authorization failed: {}", e.getMessage(), e);
            this.currentStatus = new ProviderConnectionStatus(
                    ProviderType.GMAIL, false, "Authorization Failed", null,
                    "OAuth Error: " + this.lastErrorMessage, this.lastErrorMessage, SCOPES, true
            );
            return false;
        }
    }

    @Override
    public void disconnect() {
        this.gmailService = null;
        this.lastErrorMessage = null;
        File tokensDirectory = new File(appConfig.getDataDir(), "tokens/gmail");
        if (tokensDirectory.exists()) {
            File[] files = tokensDirectory.listFiles();
            if (files != null) {
                for (File f : files) f.delete();
            }
        }
        updateStatus();
        log.info("Gmail account disconnected and local OAuth tokens purged.");
    }

    @Override
    public List<EmailMessage> fetchRecentMessages(int maxMessages) throws ProviderException {
        if (gmailService == null) {
            throw new ProviderException("Gmail provider is not authenticated. Please connect your Google account first.");
        }

        List<EmailMessage> resultList = new ArrayList<>();
        try {
            int limit = Math.max(1, Math.min(100, maxMessages));
            ListMessagesResponse listResponse = gmailService.users().messages().list("me")
                    .setMaxResults((long) limit)
                    .execute();

            List<Message> messages = listResponse.getMessages();
            if (messages == null || messages.isEmpty()) {
                return resultList;
            }

            for (Message mSummary : messages) {
                String messageId = mSummary.getId();

                // Deduplication check
                if (caseRepository != null && caseRepository.hasEmailBeenProcessed(messageId)) {
                    continue;
                }

                // Fetch raw MIME message
                Message rawMsg = gmailService.users().messages().get("me", messageId)
                        .setFormat("raw")
                        .execute();

                if (rawMsg.getRaw() != null) {
                    byte[] rawBytes = Base64.getUrlDecoder().decode(rawMsg.getRaw());
                    EmailMessage parsed = emailParser.parseEmlStream(
                            new java.io.ByteArrayInputStream(rawBytes), "gmail-" + messageId + ".eml"
                    );
                    resultList.add(parsed);
                }
            }

            // Update last sync time
            if (this.currentStatus.isConnected()) {
                this.currentStatus = new ProviderConnectionStatus(
                        ProviderType.GMAIL, true, this.currentStatus.getAccountEmail(),
                        Instant.now(), "Synchronized (" + resultList.size() + " new msgs)", "", SCOPES, true
                );
            }

            return resultList;

        } catch (Exception e) {
            log.error("Failed to fetch Gmail messages: {}", e.getMessage(), e);
            throw new ProviderException("Gmail API Fetch Error: " + e.getMessage(), e);
        }
    }

    private boolean isPortAvailable(int port) {
        if (port <= 0) return false;
        try (java.net.ServerSocket ss = new java.net.ServerSocket(port)) {
            ss.setReuseAddress(true);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
