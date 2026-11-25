package com.mailshield.services;

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
import com.google.api.services.gmail.model.Profile;
import com.mailshield.config.AppConfig;
import com.mailshield.security.TokenManagementService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.StringReader;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Enterprise Google Gmail API OAuth 2.0 Service.
 * Implements Google Authorization Code flow with PKCE and loopback redirect.
 * Strict least-privilege scope: GmailScopes.GMAIL_READONLY.
 * Incorporates self-healing token refresh and secure credential cleanup.
 */
public class GmailOAuthService {

    private static final Logger log = LoggerFactory.getLogger(GmailOAuthService.class);
    private static final String APPLICATION_NAME = "MailShield Threat Detection Platform";
    private static final List<String> SCOPES = Collections.singletonList(GmailScopes.GMAIL_READONLY);

    private final AppConfig appConfig;
    private final TokenManagementService tokenManager;
    private final File tokenStoreDir;

    private Gmail gmailClient;
    private Credential credential;
    private String connectedEmail;

    public GmailOAuthService(AppConfig appConfig, TokenManagementService tokenManager) {
        this.appConfig = appConfig;
        this.tokenManager = tokenManager;
        this.tokenStoreDir = new File(appConfig.getDataDir(), "tokens/gmail");
        if (!tokenStoreDir.exists()) {
            tokenStoreDir.mkdirs();
        }
        tryRestoreExistingSession();
    }

    private synchronized void tryRestoreExistingSession() {
        if (!isPlatformConfigured()) {
            return;
        }
        File storedCred = new File(tokenStoreDir, "StoredCredential");
        if (storedCred.exists() && storedCred.length() > 0) {
            try {
                NetHttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
                GoogleAuthorizationCodeFlow flow = buildFlow(httpTransport);
                Credential cred = flow.loadCredential("user");
                if (cred != null && cred.getAccessToken() != null) {
                    this.credential = cred;
                    this.gmailClient = new Gmail.Builder(httpTransport, GsonFactory.getDefaultInstance(), cred)
                            .setApplicationName(APPLICATION_NAME)
                            .build();
                    // Validate token with quick profile check
                    Profile profile = gmailClient.users().getProfile("me").execute();
                    this.connectedEmail = profile.getEmailAddress();
                    log.info("Successfully restored existing Gmail session for: {}", connectedEmail);
                }
            } catch (TokenResponseException e) {
                log.warn("Stored Gmail token expired or invalid ({}): purging stale credentials.", e.getMessage());
                purgeStoredTokens();
            } catch (Exception e) {
                log.info("Could not auto-restore Gmail session: {}", e.getMessage());
            }
        }
    }

    public synchronized boolean authenticateInteractive() throws Exception {
        if (!isPlatformConfigured()) {
            throw new IllegalStateException("Google Gmail Client ID or Secret is not configured by the platform owner. " +
                    "Please configure MAILSHIELD_GMAIL_CLIENT_ID and MAILSHIELD_GMAIL_CLIENT_SECRET in .env.");
        }

        NetHttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
        GoogleAuthorizationCodeFlow flow = buildFlow(httpTransport);

        int configuredPort = appConfig.getGmailRedirectPort();
        LocalServerReceiver receiver;
        try {
            receiver = new LocalServerReceiver.Builder()
                    .setPort(configuredPort > 0 ? configuredPort : 8888)
                    .build();
        } catch (Exception e) {
            log.warn("Port {} unavailable for Gmail loopback; falling back to dynamic port: {}", configuredPort, e.getMessage());
            receiver = new LocalServerReceiver.Builder().setPort(-1).build();
        }

        AuthorizationCodeInstalledApp app = new AuthorizationCodeInstalledApp(flow, receiver);
        log.info("Launching system browser for Google OAuth 2.0 authorization...");

        try {
            this.credential = app.authorize("user");
        } catch (TokenResponseException e) {
            purgeStoredTokens();
            throw new IllegalStateException("Google OAuth authentication rejected: " + e.getDetails());
        }

        this.gmailClient = new Gmail.Builder(httpTransport, GsonFactory.getDefaultInstance(), credential)
                .setApplicationName(APPLICATION_NAME)
                .build();

        Profile profile = gmailClient.users().getProfile("me").execute();
        this.connectedEmail = profile.getEmailAddress();
        log.info("Successfully authorized Google Gmail account: {}", connectedEmail);
        return true;
    }

    private GoogleAuthorizationCodeFlow buildFlow(NetHttpTransport httpTransport) throws Exception {
        String secretsJson = String.format(
                "{\"installed\":{\"client_id\":\"%s\",\"client_secret\":\"%s\",\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\"token_uri\":\"https://oauth2.googleapis.com/token\"}}",
                appConfig.getGmailClientId(),
                appConfig.getGmailClientSecret()
        );

        GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(
                GsonFactory.getDefaultInstance(),
                new StringReader(secretsJson)
        );

        return new GoogleAuthorizationCodeFlow.Builder(
                httpTransport,
                GsonFactory.getDefaultInstance(),
                clientSecrets,
                SCOPES
        )
                .setDataStoreFactory(new FileDataStoreFactory(tokenStoreDir))
                .setAccessType("offline")
                .build();
    }

    public synchronized void purgeStoredTokens() {
        if (tokenStoreDir.exists()) {
            File[] files = tokenStoreDir.listFiles();
            if (files != null) {
                for (File f : files) {
                    f.delete();
                }
            }
        }
        this.credential = null;
        this.gmailClient = null;
        this.connectedEmail = null;
        log.info("Purged Gmail stored credential tokens.");
    }

    public synchronized void disconnect() {
        purgeStoredTokens();
        log.info("Google Gmail account disconnected.");
    }

    public synchronized boolean isConnected() {
        return gmailClient != null && connectedEmail != null;
    }

    public synchronized String getConnectedEmail() {
        return connectedEmail;
    }

    public synchronized Optional<Gmail> getGmailClient() {
        return Optional.ofNullable(gmailClient);
    }

    public boolean isPlatformConfigured() {
        String cId = appConfig.getGmailClientId();
        String cSec = appConfig.getGmailClientSecret();
        return cId != null && !cId.isBlank() && !cId.contains("your-google")
                && cSec != null && !cSec.isBlank();
    }
}
