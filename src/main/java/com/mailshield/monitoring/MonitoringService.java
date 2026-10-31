package com.mailshield.monitoring;

import com.mailshield.model.MonitoringStatus;
import com.mailshield.model.ProviderType;

/**
 * Service contract for inbox synchronization and background polling.
 */
public interface MonitoringService {

    /**
     * Start continuous background monitoring for the active provider.
     */
    void startMonitoring();

    /**
     * Pause continuous monitoring.
     */
    void pauseMonitoring();

    /**
     * Resume continuous monitoring.
     */
    void resumeMonitoring();

    /**
     * Stop monitoring completely and release worker threads.
     */
    void stopMonitoring();

    /**
     * Trigger an immediate single on-demand synchronization pass.
     *
     * @param maxMessages limit of messages to fetch
     * @return count of newly analyzed messages
     */
    int triggerOnDemandSync(int maxMessages);

    /**
     * Retrieve the current truthful monitoring status.
     */
    MonitoringStatus getStatus();

    /**
     * Configure poll interval.
     */
    void setPollIntervalSeconds(int seconds);

    /**
     * Set active provider to monitor.
     */
    void setActiveProvider(ProviderType providerType);
}

