package com.mailshield.services;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.mailshield.config.AppConfig;
import com.mailshield.security.TokenManagementService;
import com.microsoft.aad.msal4j.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;

/**
 * Enterprise Microsoft Identity Platform (Entra ID) OAuth 2.0 & Graph API Service.
 * Implements Authorization Code Flow with PKCE and system browser loopback redirect.
 * Utilizes least-privilege delegated scopes (Mail.Read + User.Read).
 * Manages encrypted token caches at rest via AES-256-GCM TokenManagementService.
 */
public class OutlookOAuthService {

    private static final Logger log = LoggerFactory.getLogger(OutlookOAuthService.class);
    private static final String CACHE_KEY = "msal_outlook_cache";
    public static final String DEFAULT_MICROSOFT_CLIENT_ID = "14d82eec-204b-4c5f-a7ae-71e46e3ebc21"; // Microsoft Graph Multi-Tenant Public Client ID
    private static final String DEFAULT_AUTHORITY = "https://login.microsoftonline.com/";
    private static final Set<String> SCOPES = Set.of("https://graph.microsoft.com/Mail.Read", "User.Read");
    private static final String GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0";
    private static final int DEFAULT_REDIRECT_PORT = 8889;

    private final AppConfig appConfig;
    private final TokenManagementService tokenManager;
    private final Gson gson = new Gson();

    private PublicClientApplication pca;
    private IAuthenticationResult currentAuth;
    private String connectedEmail;
    private String connectedDisplayName;

    public OutlookOAuthService(AppConfig appConfig, TokenManagementService tokenManager) {
        this.appConfig = appConfig;
        this.tokenManager = tokenManager;
        initializePca();
    }

    public String getEffectiveClientId() {
        String clientId = appConfig.getOutlookClientId();
        if (clientId != null && !clientId.isBlank() && !clientId.contains("your-microsoft")) {
            return clientId.trim();
        }
        return DEFAULT_MICROSOFT_CLIENT_ID;
    }

    private synchronized void initializePca() {
        String clientId = getEffectiveClientId();

        try {
            String tenantId = appConfig.getOutlookTenantId();
            String authority = DEFAULT_AUTHORITY + (tenantId != null && !tenantId.isBlank() && !tenantId.contains("your-") ? tenantId : "common");

            this.pca = PublicClientApplication.builder(clientId)
                    .authority(authority)
                    .build();

            // Restore encrypted token cache from vault if available
            Optional<String> cached = tokenManager.loadDecryptedString(CACHE_KEY);
            if (cached.isPresent() && !cached.get().isBlank()) {
                pca.tokenCache().deserialize(cached.get());
                log.info("Restored encrypted MSAL token cache from AES-256-GCM vault.");
                // Attempt silent authentication with restored cache
                trySilentAuth();
            }
        } catch (Exception e) {
            log.warn("Failed to initialize MSAL PublicClientApplication: {}", e.getMessage());
        }
    }

    /**
     * Tries silent token acquisition using refresh token from cache.
     */
    public synchronized boolean trySilentAuth() {
        if (pca == null) return false;
        try {
            Set<IAccount> accounts = pca.getAccounts().join();
            if (accounts.isEmpty()) {
                return false;
            }
            IAccount account = accounts.iterator().next();
            SilentParameters parameters = SilentParameters.builder(SCOPES, account).build();
            this.currentAuth = pca.acquireTokenSilently(parameters).join();
            persistTokenCache();
            fetchUserProfile();
            log.info("Silently authenticated Microsoft account: {}", connectedEmail);
            return true;
        } catch (Exception e) {
            log.info("Silent MSAL authentication unavailable (token expired or not present): {}", e.getMessage());
            return false;
        }
    }

    /**
     * Initiates official Microsoft OAuth 2.0 interactive login in the user's default browser.
     * Completes token exchange via local loopback listener (http://localhost:8889).
     */
    public synchronized IAuthenticationResult authenticateInteractive() throws Exception {
        if (pca == null) {
            initializePca();
        }

        URI redirectUri = URI.create("http://localhost:" + DEFAULT_REDIRECT_PORT);
        InteractiveRequestParameters parameters = InteractiveRequestParameters.builder(redirectUri)
                .scopes(SCOPES)
                .prompt(Prompt.SELECT_ACCOUNT)
                .build();

        log.info("Launching system browser for Microsoft Entra OAuth2 flow on {}", redirectUri);
        this.currentAuth = pca.acquireToken(parameters).join();

        persistTokenCache();
        fetchUserProfile();
        log.info("Successfully authorized Microsoft Outlook account: {}", connectedEmail);
        return currentAuth;
    }

    private void persistTokenCache() {
        if (pca != null) {
            try {
                String serialized = pca.tokenCache().serialize();
                tokenManager.saveEncryptedString(CACHE_KEY, serialized);
            } catch (Exception e) {
                log.warn("Failed to persist encrypted MSAL token cache: {}", e.getMessage());
            }
        }
    }

    private void fetchUserProfile() {
        if (currentAuth == null) return;
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(GRAPH_ENDPOINT + "/me?$select=displayName,mail,userPrincipalName"))
                    .header("Authorization", "Bearer " + currentAuth.accessToken())
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JsonObject json = gson.fromJson(response.body(), JsonObject.class);
                if (json.has("mail") && !json.get("mail").isJsonNull()) {
                    this.connectedEmail = json.get("mail").getAsString();
                } else if (json.has("userPrincipalName")) {
                    this.connectedEmail = json.get("userPrincipalName").getAsString();
                }
                if (json.has("displayName") && !json.get("displayName").isJsonNull()) {
                    this.connectedDisplayName = json.get("displayName").getAsString();
                }
            }
        } catch (Exception e) {
            log.warn("Failed to query Microsoft Graph user profile: {}", e.getMessage());
            if (currentAuth.account() != null) {
                this.connectedEmail = currentAuth.account().username();
            }
        }
        if (this.connectedEmail == null && currentAuth.account() != null) {
            this.connectedEmail = currentAuth.account().username();
        }
    }

    /**
     * Disconnects the Microsoft account, wipes cached credentials from memory,
     * and securely deletes the encrypted token cache from the vault.
     */
    public synchronized void disconnect() {
        if (pca != null) {
            try {
                Set<IAccount> accounts = pca.getAccounts().join();
                for (IAccount account : accounts) {
                    pca.removeAccount(account).join();
                }
            } catch (Exception e) {
                log.warn("Error clearing MSAL accounts: {}", e.getMessage());
            }
        }
        tokenManager.deleteToken(CACHE_KEY);
        this.currentAuth = null;
        this.connectedEmail = null;
        this.connectedDisplayName = null;
        log.info("Microsoft Outlook account disconnected and encrypted token vault purged.");
    }

    public synchronized boolean isConnected() {
        return currentAuth != null && connectedEmail != null;
    }

    public synchronized String getConnectedEmail() {
        return connectedEmail;
    }

    public synchronized String getConnectedDisplayName() {
        return connectedDisplayName != null ? connectedDisplayName : connectedEmail;
    }

    public synchronized Optional<String> getValidAccessToken() {
        if (currentAuth == null) {
            if (!trySilentAuth()) {
                return Optional.empty();
            }
        }
        // If token expiration is near, refresh silently
        if (currentAuth != null && currentAuth.expiresOnDate() != null) {
            long remainingMillis = currentAuth.expiresOnDate().getTime() - System.currentTimeMillis();
            if (remainingMillis < 60_000) { // less than 60 seconds remaining
                log.info("Microsoft Graph access token expiring in {}ms, refreshing silently...", remainingMillis);
                if (!trySilentAuth()) {
                    return Optional.empty();
                }
            }
            return Optional.of(currentAuth.accessToken());
        }
        return currentAuth != null ? Optional.of(currentAuth.accessToken()) : Optional.empty();
    }

    public boolean isPlatformConfigured() {
        return getEffectiveClientId() != null && !getEffectiveClientId().isBlank();
    }
}
