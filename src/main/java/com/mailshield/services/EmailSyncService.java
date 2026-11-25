package com.mailshield.services;

import com.mailshield.model.EmailMessage;
import com.mailshield.model.ProviderType;
import com.mailshield.providers.EmailProvider;
import com.mailshield.storage.CaseRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Enterprise Email Synchronization Service.
 * Manages incremental email retrieval across all authenticated mailboxes (Gmail, Outlook).
 * Enforces deduplication against SQLite repository, manages provider rate limits,
 * pipes messages into the analysis pipeline, and streams live sync events.
 */
public class EmailSyncService {

    private static final Logger log = LoggerFactory.getLogger(EmailSyncService.class);

    private final Map<ProviderType, EmailProvider> providers;
    private final EmailAnalysisService analysisService;
    private final CaseRepository caseRepository;
    private final NotificationService notificationService;

    private final Map<ProviderType, Instant> lastSyncTimes = new ConcurrentHashMap<>();
    private final AtomicBoolean isSyncing = new AtomicBoolean(false);

    public EmailSyncService(Map<ProviderType, EmailProvider> providers,
                            EmailAnalysisService analysisService,
                            CaseRepository caseRepository,
                            NotificationService notificationService) {
        this.providers = providers;
        this.analysisService = analysisService;
        this.caseRepository = caseRepository;
        this.notificationService = notificationService;
    }

    /**
     * Executes an incremental sync pass for the given provider.
     * Returns the count of new emails ingested and analyzed.
     */
    public synchronized int syncProvider(ProviderType providerType, int maxMessages) {
        EmailProvider provider = providers.get(providerType);
        if (provider == null || !provider.getStatus().isConnected()) {
            log.info("Skipping sync for {}: Provider is not connected.", providerType);
            return 0;
        }

        log.info("Starting synchronization pass for {} (max {} messages)...", providerType.getTitle(), maxMessages);
        if (notificationService != null) {
            notificationService.publishSyncProgress(providerType, "Starting synchronization...", 0);
        }

        int newEmailsCount = 0;
        try {
            List<EmailMessage> fetched = provider.fetchRecentMessages(maxMessages);
            for (EmailMessage email : fetched) {
                // Deduplication check
                if (caseRepository != null && caseRepository.hasEmailBeenProcessed(email.getProviderMessageId())) {
                    continue;
                }
                analysisService.processAndPersist(email);
                newEmailsCount++;
            }

            lastSyncTimes.put(providerType, Instant.now());
            if (caseRepository != null) {
                caseRepository.saveCheckpoint(providerType.name(), Instant.now().toString());
            }

            log.info("Sync pass completed for {}: {} new emails analyzed.", providerType.getTitle(), newEmailsCount);
            if (notificationService != null) {
                notificationService.publishSyncProgress(providerType,
                        "Synchronized " + newEmailsCount + " new messages successfully.", newEmailsCount);
            }
        } catch (Exception e) {
            log.error("Sync failed for {}: {}", providerType.getTitle(), e.getMessage(), e);
            if (notificationService != null) {
                notificationService.publishSyncProgress(providerType, "Sync failed: " + e.getMessage(), 0);
            }
        }

        return newEmailsCount;
    }

    /**
     * Synchronizes all currently connected mailboxes.
     */
    public synchronized int syncAllConnected(int maxPerProvider) {
        if (!isSyncing.compareAndSet(false, true)) {
            log.info("A synchronization pass is already running.");
            return 0;
        }
        int totalNew = 0;
        try {
            for (Map.Entry<ProviderType, EmailProvider> entry : providers.entrySet()) {
                if (entry.getValue().getStatus().isConnected()) {
                    totalNew += syncProvider(entry.getKey(), maxPerProvider);
                }
            }
        } finally {
            isSyncing.set(false);
        }
        return totalNew;
    }

    public boolean hasAnyConnectedProvider() {
        return providers.values().stream().anyMatch(p -> p.getStatus().isConnected());
    }

    public Instant getLastSyncTime(ProviderType providerType) {
        return lastSyncTimes.get(providerType);
    }

    public boolean isCurrentlySyncing() {
        return isSyncing.get();
    }
}
