package com.mailshield.providers;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.mailshield.config.AppConfig;
import com.mailshield.ingestion.EmailParser;
import com.mailshield.model.EmailMessage;
import com.mailshield.model.ProviderConnectionStatus;
import com.mailshield.model.ProviderType;
import com.mailshield.storage.CaseRepository;
import com.microsoft.aad.msal4j.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Official Microsoft Graph API & Outlook/365 integration using MSAL Java.
 * Uses delegated authentication with the minimum required scope: Mail.Read.
 * Never requests or collects Microsoft user passwords.
 */
public class MicrosoftOutlookProvider implements OutlookProvider {

    private static final Logger log = LoggerFactory.getLogger(MicrosoftOutlookProvider.class);
    private static final Set<String> SCOPES = Set.of("https://graph.microsoft.com/Mail.Read", "User.Read");
    private static final String GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0";

    private final EmailParser emailParser;
    private final CaseRepository caseRepository;
    private final AppConfig appConfig;
    private HttpClient httpClient;
    private final Gson gson = new Gson();

    private String clientId;
    private String tenantId;
    private IAuthenticationResult authResult;
    private ProviderConnectionStatus currentStatus;
    private String lastErrorMessage;

    public MicrosoftOutlookProvider(EmailParser emailParser, CaseRepository caseRepository, AppConfig appConfig) {
        this.emailParser = emailParser;
        this.caseRepository = caseRepository;
        this.appConfig = appConfig;
        this.clientId = appConfig.getOutlookClientId();
        this.tenantId = appConfig.getOutlookTenantId();
        updateStatus();
    }

    private synchronized HttpClient getHttpClient() {
        if (this.httpClient == null) {
            try {
                this.httpClient = HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(15))
                        .build();
            } catch (Exception e) {
                log.warn("NIO HttpClient initialization failed (environment restricted): {}", e.getMessage());
            }
        }
        return this.httpClient;
    }

    private void updateStatus() {
        if (!hasStoredCredentials()) {
            this.currentStatus = ProviderConnectionStatus.notConfigured(ProviderType.OUTLOOK);
        } else if (authResult == null) {
            this.currentStatus = new ProviderConnectionStatus(
                    ProviderType.OUTLOOK, false, "Ready to Connect",
                    null, "Credentials Configured (Awaiting Sign-In)", "", new ArrayList<>(SCOPES), true
            );
        }
    }

    @Override
    public ProviderType getProviderType() {
        return ProviderType.OUTLOOK;
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
    public void setCredentials(String clientId, String tenantId) {
        this.clientId = clientId;
        this.tenantId = tenantId;
        updateStatus();
    }

    @Override
    public boolean hasStoredCredentials() {
        return clientId != null && !clientId.isBlank() && !clientId.contains("your-microsoft");
    }

    @Override
    public boolean testConnection() {
        if (!hasStoredCredentials() || authResult == null) return false;
        try {
            HttpClient client = getHttpClient();
            if (client == null) return false;
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(GRAPH_ENDPOINT + "/me"))
                    .header("Authorization", "Bearer " + authResult.accessToken())
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200;
        } catch (Exception e) {
            log.warn("Outlook Graph connection test failed: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public boolean authenticate() {
        if (!hasStoredCredentials()) {
            this.currentStatus = ProviderConnectionStatus.notConfigured(ProviderType.OUTLOOK);
            return false;
        }

        try {
            String authority = "https://login.microsoftonline.com/" + (tenantId != null ? tenantId : "common");
            PublicClientApplication pca = PublicClientApplication.builder(clientId)
                    .authority(authority)
                    .build();

            // Use Device Code Flow (Ideal for desktop CLI and non-browser apps without needing local open ports)
            DeviceCodeFlowParameters parameters = DeviceCodeFlowParameters.builder(
                    SCOPES,
                    deviceCode -> {
                        log.info("Microsoft Sign-In Device Flow: {}", deviceCode.message());
                        System.out.println("\n=======================================================");
                        System.out.println("MICROSOFT OUTLOOK AUTHENTICATION REQUIRED:");
                        System.out.println(deviceCode.message());
                        System.out.println("=======================================================\n");
                    }
            ).build();

            this.authResult = pca.acquireToken(parameters).join();
            String accountUsername = authResult.account() != null ? authResult.account().username() : "Microsoft 365 User";

            this.currentStatus = new ProviderConnectionStatus(
                    ProviderType.OUTLOOK, true, accountUsername, Instant.now(),
                    "Connected (Authorized via Microsoft Entra)", "", new ArrayList<>(SCOPES), true
            );
            log.info("Microsoft Graph successfully authorized for: {}", accountUsername);
            return true;

        } catch (Exception e) {
            this.lastErrorMessage = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            log.error("Microsoft Entra authentication failed: {}", e.getMessage(), e);
            this.currentStatus = new ProviderConnectionStatus(
                    ProviderType.OUTLOOK, false, "Authorization Failed", null,
                    "MSAL Error: " + this.lastErrorMessage, this.lastErrorMessage, new ArrayList<>(SCOPES), true
            );
            return false;
        }
    }

    @Override
    public void disconnect() {
        this.authResult = null;
        this.currentStatus = ProviderConnectionStatus.disconnected(ProviderType.OUTLOOK, "Not Signed In");
        log.info("Microsoft Outlook connection disconnected.");
    }

    @Override
    public List<EmailMessage> fetchRecentMessages(int maxMessages) throws ProviderException {
        if (authResult == null) {
            throw new ProviderException("Microsoft Outlook provider is not authenticated. Please sign in via Microsoft Entra.");
        }

        List<EmailMessage> resultList = new ArrayList<>();
        try {
            HttpClient client = getHttpClient();
            if (client == null) {
                throw new ProviderException("HTTP client unavailable in current environment.");
            }
            int limit = Math.max(1, Math.min(50, maxMessages));
            // 1. Query message list from Microsoft Graph
            String listUrl = String.format("%s/me/mailFolders/inbox/messages?$top=%d&$select=id,subject", GRAPH_ENDPOINT, limit);
            HttpRequest listRequest = HttpRequest.newBuilder()
                    .uri(URI.create(listUrl))
                    .header("Authorization", "Bearer " + authResult.accessToken())
                    .GET()
                    .build();

            HttpResponse<String> listResponse = client.send(listRequest, HttpResponse.BodyHandlers.ofString());
            if (listResponse.statusCode() != 200) {
                throw new ProviderException("Graph API returned error status: " + listResponse.statusCode() + " - " + listResponse.body());
            }

            JsonObject json = gson.fromJson(listResponse.body(), JsonObject.class);
            JsonArray valueArray = json.getAsJsonArray("value");
            if (valueArray == null || valueArray.isEmpty()) {
                return resultList;
            }

            for (JsonElement elem : valueArray) {
                JsonObject msgObj = elem.getAsJsonObject();
                String messageId = msgObj.get("id").getAsString();

                // Deduplication check
                if (caseRepository != null && caseRepository.hasEmailBeenProcessed(messageId)) {
                    continue;
                }

                // 2. Fetch full raw RFC 822 MIME bytes from Graph API endpoint: /me/messages/{id}/$value
                String rawMimeUrl = String.format("%s/me/messages/%s/$value", GRAPH_ENDPOINT, messageId);
                HttpRequest rawRequest = HttpRequest.newBuilder()
                        .uri(URI.create(rawMimeUrl))
                        .header("Authorization", "Bearer " + authResult.accessToken())
                        .GET()
                        .build();

                HttpResponse<byte[]> rawResponse = client.send(rawRequest, HttpResponse.BodyHandlers.ofByteArray());
                if (rawResponse.statusCode() == 200) {
                    byte[] rawBytes = rawResponse.body();
                    EmailMessage parsed = emailParser.parseEmlStream(
                            new ByteArrayInputStream(rawBytes),
                            "Outlook Graph Message ID: " + messageId
                    );

                    EmailMessage normalized = EmailMessage.builder()
                            .id(parsed.getId())
                            .providerMessageId(messageId)
                            .providerSource(ProviderType.OUTLOOK)
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
            }

            this.currentStatus = new ProviderConnectionStatus(
                    ProviderType.OUTLOOK, true, currentStatus.getAccountEmail(),
                    Instant.now(), "Sync Completed (" + resultList.size() + " new messages)",
                    "", new ArrayList<>(SCOPES), true
            );

        } catch (Exception e) {
            log.error("Failed to fetch messages from Microsoft Graph: {}", e.getMessage(), e);
            throw new ProviderException("Failed to fetch Outlook messages: " + e.getMessage(), e);
        }

        return resultList;
    }
}
