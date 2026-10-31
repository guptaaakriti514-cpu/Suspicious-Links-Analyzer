package com.mailshield.monitoring;

import com.mailshield.detection.DetectionEngine;
import com.mailshield.forensics.EvidenceManager;
import com.mailshield.model.*;
import com.mailshield.providers.EmailProvider;
import com.mailshield.storage.CaseRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Robust background email inbox monitoring service.
 * Supports Mode A (on-demand manual sync) and Mode B (scheduled continuous polling with pause/resume).
 * Handles thread isolation, checkpoints, deduplication, and graceful shutdown.
 */
public class DefaultMonitoringService implements MonitoringService {

    private static final Logger log = LoggerFactory.getLogger(DefaultMonitoringService.class);

    private final Map<ProviderType, EmailProvider> providers;
    private final DetectionEngine detectionEngine;
    private final CaseRepository caseRepository;
    private final EvidenceManager evidenceManager;

    private ProviderType activeProviderType = ProviderType.GMAIL;
    private int pollIntervalSeconds = 60;
    private int maxMessagesPerPass = 25;

    private ScheduledExecutorService scheduler;
    private ScheduledFuture<?> pollingTask;
    private final AtomicBoolean isPaused = new AtomicBoolean(false);
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private final AtomicInteger processedCount = new AtomicInteger(0);

    private Instant lastPollTime;
    private String lastError = "";

    public DefaultMonitoringService(Map<ProviderType, EmailProvider> providers,
                                    DetectionEngine detectionEngine,
                                    CaseRepository caseRepository,
                                    EvidenceManager evidenceManager) {
        this.providers = providers;
        this.detectionEngine = detectionEngine;
        this.caseRepository = caseRepository;
        this.evidenceManager = evidenceManager;
    }

    @Override
    public synchronized void startMonitoring() {
        if (isRunning.get()) {
            log.info("Monitoring service is already active.");
            return;
        }

        EmailProvider provider = providers.get(activeProviderType);
        if (provider == null || !provider.getStatus().isConnected()) {
            this.lastError = "Selected provider (" + activeProviderType.getTitle() + ") is not connected.";
            log.warn("Cannot start monitoring: provider is not connected.");
            return;
        }

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "MailShield-InboxMonitor");
            t.setDaemon(true);
            return t;
        });

        isRunning.set(true);
        isPaused.set(false);
        lastError = "";

        pollingTask = scheduler.scheduleWithFixedDelay(
                this::pollCycle,
                0,
                pollIntervalSeconds,
                TimeUnit.SECONDS
        );

        log.info("Continuous inbox monitoring started for {} with interval of {}s",
                activeProviderType.getTitle(), pollIntervalSeconds);
    }

    private void pollCycle() {
        if (isPaused.get()) {
            return;
        }

        try {
            lastPollTime = Instant.now();
            int newCount = triggerOnDemandSync(maxMessagesPerPass);
            processedCount.addAndGet(newCount);
            if (caseRepository != null) {
                caseRepository.saveCheckpoint(activeProviderType.name(), lastPollTime.toString());
            }
        } catch (Exception e) {
            this.lastError = e.getMessage();
            log.error("Monitoring poll cycle encountered error: {}", e.getMessage());
        }
    }

    @Override
    public synchronized void pauseMonitoring() {
        if (isRunning.get()) {
            isPaused.set(true);
            log.info("Monitoring paused by user.");
        }
    }

    @Override
    public synchronized void resumeMonitoring() {
        if (isRunning.get()) {
            isPaused.set(false);
            log.info("Monitoring resumed by user.");
        }
    }

    @Override
    public synchronized void stopMonitoring() {
        isRunning.set(false);
        isPaused.set(false);
        if (pollingTask != null) {
            pollingTask.cancel(true);
            pollingTask = null;
        }
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
        log.info("Monitoring stopped.");
    }

    @Override
    public int triggerOnDemandSync(int maxMessages) {
        EmailProvider provider = providers.get(activeProviderType);
        if (provider == null || !provider.getStatus().isConnected()) {
            this.lastError = "Active provider is not connected.";
            return 0;
        }

        int count = 0;
        try {
            List<EmailMessage> newEmails = provider.fetchRecentMessages(maxMessages);
            for (EmailMessage email : newEmails) {
                // Run automated detection pipeline
                AnalysisResult result = detectionEngine.analyzeEmail(email);
                count++;

                // Persist email & analysis
                if (caseRepository != null) {
                    caseRepository.saveEmailMessage(email);
                    caseRepository.saveAnalysisResult(result);
                }

                // Record forensic evidence
                if (evidenceManager != null) {
                    evidenceManager.recordEvidence(email, null, provider.getProviderType().getTitle());
                }

                // If high or critical risk, automatically open an investigation case
                if (caseRepository != null && (result.getRiskAssessment().getRiskLevel() == RiskLevel.CRITICAL ||
                        result.getRiskAssessment().getRiskLevel() == RiskLevel.HIGH)) {
                    InvestigationCase autoCase = InvestigationCase.builder()
                            .caseId("CASE-" + System.currentTimeMillis() + "-" + count)
                            .title("Automated Threat Alert: " + email.getSubject())
                            .status(CaseStatus.OPEN)
                            .priority(result.getRiskAssessment().getRiskLevel() == RiskLevel.CRITICAL ? CasePriority.CRITICAL : CasePriority.HIGH)
                            .createdAt(Instant.now())
                            .analystNotes("Case automatically generated during monitoring sync. Severity: " + result.getRiskAssessment().getRiskLevel().getLabel())
                            .associatedMessageIds(List.of(email.getId()))
                            .analysisResultIds(List.of(result.getAnalysisId()))
                            .tags(List.of("AutomatedAlert", activeProviderType.name(), result.getRiskAssessment().getRiskLevel().name()))
                            .build();
                    caseRepository.saveCase(autoCase);
                }
            }
            this.lastError = "";
        } catch (Exception e) {
            this.lastError = e.getMessage();
            log.error("On-demand synchronization error: {}", e.getMessage(), e);
        }
        return count;
    }

    @Override
    public MonitoringStatus getStatus() {
        EmailProvider provider = providers.get(activeProviderType);
        if (provider == null || !provider.getStatus().isConfigured()) {
            return MonitoringStatus.notConfigured();
        }

        if (!provider.getStatus().isConnected()) {
            return new MonitoringStatus(MonitoringState.DISCONNECTED, lastPollTime, pollIntervalSeconds,
                    processedCount.get(), "Provider not authorized or disconnected", activeProviderType);
        }

        if (!lastError.isBlank()) {
            return new MonitoringStatus(MonitoringState.ERROR, lastPollTime, pollIntervalSeconds,
                    processedCount.get(), lastError, activeProviderType);
        }

        if (isRunning.get()) {
            if (isPaused.get()) {
                return new MonitoringStatus(MonitoringState.PAUSED, lastPollTime, pollIntervalSeconds,
                        processedCount.get(), "", activeProviderType);
            }
            return new MonitoringStatus(MonitoringState.RUNNING, lastPollTime, pollIntervalSeconds,
                    processedCount.get(), "", activeProviderType);
        }

        return new MonitoringStatus(MonitoringState.NOT_CONFIGURED, lastPollTime, pollIntervalSeconds,
                processedCount.get(), "Monitoring is stopped.", activeProviderType);
    }

    @Override
    public void setPollIntervalSeconds(int seconds) {
        this.pollIntervalSeconds = Math.max(10, seconds);
    }

    @Override
    public void setActiveProvider(ProviderType providerType) {
        this.activeProviderType = providerType;
    }
}

