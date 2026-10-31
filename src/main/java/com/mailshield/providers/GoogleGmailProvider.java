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
                    ProviderType.GMAIL, false, "Awaiting User OAuth Consent",
                    null, "Disconnected", "", SCOPES, true
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
    public void setCredentials(String clientId, String clientSecret, int redirectPort) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectPort = redirectPort;
        updateStatus();
    }

    @Override
    public boolean hasStoredCredentials() {
        return clientId != null && !clientId.isBlank() && !clientId.contains("your-google");
    }

    @Override
    public boolean testConnection() {
        if (!hasStoredCredentials()) return false;
        if (gmailService == null) return false;
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
        if (!hasStoredCredentials()) {
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

            LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(redirectPort).build();
            Credential credential = new AuthorizationCodeInstalledApp(flow, receiver).authorize("user");

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
            log.error("Gmail OAuth authorization failed: {}", e.getMessage(), e);
            this.currentStatus = new ProviderConnectionStatus(
                    ProviderType.GMAIL, false, "Authorization Failed", null,
                    "OAuth Error: " + e.getMessage(), e.getMessage(), SCOPES, true
            );
            return false;
        }
    }

    @Override
    public void disconnect() {
        this.gmailService = null;
        File tokensDirectory = new File(appConfig.getDataDir(), "tokens/gmail");
        if (tokensDirectory.exists()) {
            File[] files = tokensDirectory.listFiles();
            if (files != null) {
                for (File f : files) f.delete();
            }
        }
        this.currentStatus = ProviderConnectionStatus.disconnected(ProviderType.GMAIL, "Not Signed In");
        log.info("Gmail account disconnected and local OAuth tokens purged.");
    }

    @Override
    public List<EmailMessage> fetchRecentMessages(int maxMessages) throws ProviderException {
        if (gmailService == null) {
            throw new ProviderException("Gmail provider is not authenticated. Please connect your Google account in settings.");
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

                // Retrieve raw message bytes
                Message fullMsg = gmailService.users().messages().get("me", messageId)
                        .setFormat("raw")
                        .execute();

                byte[] rawBytes = Base64.getUrlDecoder().decode(fullMsg.getRaw());
                EmailMessage parsed = emailParser.parseEmlStream(
                        new java.io.ByteArrayInputStream(rawBytes),
                        "Gmail Message ID: " + messageId
                );

                // Set provider ID to guarantee deduplication
                EmailMessage normalized = EmailMessage.builder()
                        .id(parsed.getId())
                        .providerMessageId(messageId)
                        .providerSource(ProviderType.GMAIL)
                        .from(parsed.getFrom())
                        .fromDisplayName(parsed.getFromDisplayName())
                        .fromAddress(parsed.getFromAddress())
                        .replyTo(parsed.getReplyTo())
                        .returnPath(parsed.getReturnPath())
                        .to(parsed.getTo())
                        .cc(parsed.getCc())
                        .bcc(parsed.getBcc())
                        .subject(parsed.getSubject())
                        .date(parsed.getDate())
                        .messageIdHeader(parsed.getMessageIdHeader())
                        .headers(parsed.getHeaders())
                        .bodyText(parsed.getBodyText())
                        .bodyHtml(parsed.getBodyHtml())
                        .attachments(parsed.getAttachments())
                        .extractedUrls(parsed.getExtractedUrls())
                        .authResult(parsed.getAuthResult())
                        .rawBytes(rawBytes)
                        .rawSha256(parsed.getRawSha256())
                        .ingestedAt(Instant.now())
                        .build();

                resultList.add(normalized);
                if (caseRepository != null) {
                    caseRepository.saveEmailMessage(normalized);
                }
            }

            this.currentStatus = new ProviderConnectionStatus(
                    ProviderType.GMAIL, true, currentStatus.getAccountEmail(),
                    Instant.now(), "Sync Completed (" + resultList.size() + " new messages)",
                    "", SCOPES, true
            );

        } catch (Exception e) {
            log.error("Failed to fetch messages from Gmail: {}", e.getMessage(), e);
            throw new ProviderException("Failed to fetch Gmail messages: " + e.getMessage(), e);
        }

        return resultList;
    }
}

