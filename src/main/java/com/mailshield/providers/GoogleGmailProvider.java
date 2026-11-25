package com.mailshield.providers;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.TokenResponseException;
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
        tryRestoreExistingSession();
        updateStatus();
    }

    public synchronized boolean tryRestoreExistingSession() {
        if (!hasStoredCredentials()) return false;
        File tokensDirectory = new File(appConfig.getDataDir(), "tokens/gmail");
        File storedCred = new File(tokensDirectory, "StoredCredential");
        if (!storedCred.exists() || storedCred.length() == 0) return false;

        try {
            NetHttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
            GsonFactory jsonFactory = GsonFactory.getDefaultInstance();

            String clientSecretsJson = String.format(
                    "{\"installed\":{\"client_id\":\"%s\",\"client_secret\":\"%s\",\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\"token_uri\":\"https://oauth2.googleapis.com/token\"}}",
                    clientId, clientSecret
            );
            GoogleClientSecrets secrets = GoogleClientSecrets.load(jsonFactory, new StringReader(clientSecretsJson));
            FileDataStoreFactory dataStoreFactory = new FileDataStoreFactory(tokensDirectory);
            GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                    httpTransport, jsonFactory, secrets, SCOPES)
                    .setDataStoreFactory(dataStoreFactory)
                    .setAccessType("offline")
                    .build();

            Credential credential = flow.loadCredential("user");
            if (credential != null && credential.getRefreshToken() != null) {
                log.info("Found stored Gmail session. Auto-restoring permanent connection...");
                try {
                    if (credential.getAccessToken() == null || (credential.getExpiresInSeconds() != null && credential.getExpiresInSeconds() < 60)) {
                        credential.refreshToken();
                    }
                    Gmail testService = new Gmail.Builder(httpTransport, jsonFactory, credential)
                            .setApplicationName(APPLICATION_NAME)
                            .build();
                    var profile = testService.users().getProfile("me").execute();
                    this.gmailService = testService;
                    String userEmail = profile.getEmailAddress();
                    this.currentStatus = new ProviderConnectionStatus(
                            ProviderType.GMAIL, true, userEmail, Instant.now(),
                            "Connected (Authorized via Google OAuth2)", "", SCOPES, true
                    );
                    log.info("Permanent Gmail connection auto-restored for: {}", userEmail);
                    return true;
                } catch (TokenResponseException tre) {
                    log.warn("Stored Gmail token expired or revoked ({}: {}). Purging.", tre.getStatusCode(), tre.getContent());
                    purgeStoredTokens();
                } catch (Exception ex) {
                    log.warn("Stored Gmail token validation failed ({}). Keeping for retry.", ex.getMessage());
                }
            }
        } catch (Exception e) {
            log.info("Could not auto-restore Gmail session: {}", e.getMessage());
        }
        return false;
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
            this.lastErrorMessage = "Google Gmail client credentials missing in .env configuration.";
            this.currentStatus = ProviderConnectionStatus.notConfigured(ProviderType.GMAIL);
            return false;
        }

        if (tryRestoreExistingSession()) {
            log.info("Already authenticated with valid stored Gmail session.");
            return true;
        }

        File tokensDirectory = new File(appConfig.getDataDir(), "tokens/gmail");
        if (!tokensDirectory.exists()) tokensDirectory.mkdirs();

        try {
            NetHttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
            GsonFactory jsonFactory = GsonFactory.getDefaultInstance();

            String clientSecretsJson = String.format(
                    "{\"installed\":{\"client_id\":\"%s\",\"client_secret\":\"%s\",\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\"token_uri\":\"https://oauth2.googleapis.com/token\"}}",
                    clientId, clientSecret
            );

            GoogleClientSecrets secrets = GoogleClientSecrets.load(jsonFactory, new StringReader(clientSecretsJson));

            // Phase 1: Validate existing stored token if present
            FileDataStoreFactory dataStoreFactory = new FileDataStoreFactory(tokensDirectory);
            GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                    httpTransport, jsonFactory, secrets, SCOPES)
                    .setDataStoreFactory(dataStoreFactory)
                    .setAccessType("offline")
                    .build();

            Credential credential = flow.loadCredential("user");
            if (credential != null && credential.getRefreshToken() != null) {
                log.info("Found existing stored Gmail OAuth session. Verifying token freshness with Google...");
                try {
                    boolean refreshed = credential.refreshToken();
                    if (refreshed && credential.getAccessToken() != null) {
                        Gmail testService = new Gmail.Builder(httpTransport, jsonFactory, credential)
                                .setApplicationName(APPLICATION_NAME)
                                .build();
                        var profile = testService.users().getProfile("me").execute();
                        this.gmailService = testService;
                        String userEmail = profile.getEmailAddress();
                        this.currentStatus = new ProviderConnectionStatus(
                                ProviderType.GMAIL, true, userEmail, Instant.now(),
                                "Connected (Authorized via Google OAuth2)", "", SCOPES, true
                        );
                        log.info("Stored Gmail OAuth token is valid. Connected to mailbox: {}", userEmail);
                        return true;
                    }
                } catch (TokenResponseException tre) {
                    log.warn("Stored Gmail token expired or revoked ({}: {}). Purging stale cache.", tre.getStatusCode(), tre.getContent());
                    purgeStoredTokens();
                } catch (Exception ex) {
                    log.warn("Stored Gmail token validation failed ({}). Clearing cache to force fresh sign-in.", ex.getMessage());
                    purgeStoredTokens();
                }
            }

            // Phase 2: Stored token missing or invalid - launch fresh browser-based authorization
            log.info("Initiating fresh Google OAuth2 interactive sign-in flow...");
            purgeStoredTokens();

            FileDataStoreFactory freshDataStoreFactory = new FileDataStoreFactory(tokensDirectory);
            GoogleAuthorizationCodeFlow freshFlow = new GoogleAuthorizationCodeFlow.Builder(
                    httpTransport, jsonFactory, secrets, SCOPES)
                    .setDataStoreFactory(freshDataStoreFactory)
                    .setAccessType("offline")
                    .build();

            int preferredPort = (redirectPort > 0 && isPortAvailable(redirectPort)) ? redirectPort : -1;
            try {
                LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(preferredPort).build();
                credential = new AuthorizationCodeInstalledApp(freshFlow, receiver).authorize("user");
            } catch (Exception e) {
                if (preferredPort != -1 && (e instanceof java.net.BindException || (e.getMessage() != null && e.getMessage().contains("already in use")))) {
                    log.warn("Port {} in use or in TIME_WAIT state, retrying with dynamic open port (-1)...", preferredPort);
                    LocalServerReceiver dynamicReceiver = new LocalServerReceiver.Builder().setPort(-1).build();
                    credential = new AuthorizationCodeInstalledApp(freshFlow, dynamicReceiver).authorize("user");
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
            purgeStoredTokens();
            this.lastErrorMessage = buildHelpfulErrorMessage(e);
            log.error("Gmail OAuth authorization failed: {}", this.lastErrorMessage, e);
            this.currentStatus = new ProviderConnectionStatus(
                    ProviderType.GMAIL, false, "Authorization Failed", null,
                    "OAuth Error: " + (e.getMessage() != null ? e.getMessage() : "Unknown"), this.lastErrorMessage, SCOPES, true
            );
            return false;
        }
    }

    private String buildHelpfulErrorMessage(Exception e) {
        String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
        if (msg.contains("invalid_grant")) {
            return "400 Bad Request: invalid_grant\n\n" +
                   "Google rejected the token grant. Possible root causes:\n" +
                   "• Stale / Expired Session: Stale token cache was automatically wiped. Please click 'Connect Gmail' to log in cleanly in your browser.\n" +
                   "• Test User Required: If your Google Cloud OAuth app is in 'Testing' mode, your Gmail address MUST be added under 'OAuth consent screen > Test users'.\n" +
                   "• Authorization Code Expired: Code must be exchanged within 60 seconds of browser login.\n" +
                   "• Client Secret: Verify that Client Secret matches Client ID in Google Cloud Console.\n" +
                   "• System Clock: Ensure your Windows system time is accurately synchronized with internet time.";
        }
        if (msg.contains("access_denied")) {
            return "Access Denied: Permissions were cancelled or not granted in the Google sign-in window.";
        }
        if (msg.contains("redirect_uri_mismatch")) {
            return "400 redirect_uri_mismatch:\n" +
                   "In Google Cloud Console, ensure your OAuth 2.0 Client is created as 'Desktop app' (Installed application).\n" +
                   "If configured as 'Web application', you must add http://localhost:" + redirectPort + "/Callback to Authorized Redirect URIs.";
        }
        return msg;
    }

    private void purgeStoredTokens() {
        try {
            File tokensDirectory = new File(appConfig.getDataDir(), "tokens/gmail");
            if (tokensDirectory.exists()) {
                File[] files = tokensDirectory.listFiles();
                if (files != null) {
                    for (File f : files) {
                        boolean deleted = f.delete();
                        log.debug("Purged Gmail token file {}: {}", f.getName(), deleted);
                    }
                }
            }
        } catch (Exception ex) {
            log.warn("Error purging Gmail token store: {}", ex.getMessage());
        }
    }

    @Override
    public void disconnect() {
        this.gmailService = null;
        this.lastErrorMessage = null;
        purgeStoredTokens();
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
            String errMsg = e.getMessage() != null ? e.getMessage() : "";
            if (errMsg.contains("invalid_grant") || errMsg.contains("401") || errMsg.contains("Token") || errMsg.contains("revoked")) {
                purgeStoredTokens();
                this.gmailService = null;
                this.currentStatus = new ProviderConnectionStatus(
                        ProviderType.GMAIL, false, currentStatus.getAccountEmail(),
                        null, "Session Expired (Please Reconnect)", "OAuth session expired or invalidated. Please reconnect.", SCOPES, true
                );
            }
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
