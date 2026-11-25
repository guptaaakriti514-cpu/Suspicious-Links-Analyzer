package com.mailshield.services;

import com.mailshield.model.AnalysisResult;
import com.mailshield.model.EmailMessage;
import com.mailshield.model.ProviderType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Central event bus and notification service for real-time security alerts,
 * provider connectivity changes, and sync status updates across the UI.
 */
public class NotificationService {

    private static final Logger log = LoggerFactory.getLogger(NotificationService.class);

    public record SecurityAlert(
            String id,
            Instant timestamp,
            String title,
            String details,
            String severity, // CRITICAL, HIGH, MEDIUM, INFO
            String emailId
    ) {}

    public interface NotificationListener {
        void onSecurityAlert(SecurityAlert alert);
        void onProviderStatusChanged(ProviderType providerType, boolean connected, String accountEmail);
        void onSyncProgress(ProviderType providerType, String message, int newEmailsCount);
    }

    private final List<NotificationListener> listeners = new CopyOnWriteArrayList<>();
    private final List<SecurityAlert> recentAlerts = new CopyOnWriteArrayList<>();
    private static final int MAX_RECENT_ALERTS = 50;

    public void addListener(NotificationListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    public void removeListener(NotificationListener listener) {
        listeners.remove(listener);
    }

    public void publishAlert(String title, String details, String severity, String emailId) {
        SecurityAlert alert = new SecurityAlert(
                "alert-" + System.currentTimeMillis(),
                Instant.now(),
                title,
                details,
                severity,
                emailId
        );
        recentAlerts.add(0, alert);
        if (recentAlerts.size() > MAX_RECENT_ALERTS) {
            recentAlerts.remove(recentAlerts.size() - 1);
        }
        log.info("[ALERT-{}] {}: {}", severity, title, details);
        for (NotificationListener listener : listeners) {
            try {
                listener.onSecurityAlert(alert);
            } catch (Exception e) {
                log.warn("Notification listener error: {}", e.getMessage());
            }
        }
    }

    public void publishProviderStatus(ProviderType providerType, boolean connected, String accountEmail) {
        log.info("Provider status changed: {} connected={} email={}", providerType, connected, accountEmail);
        for (NotificationListener listener : listeners) {
            try {
                listener.onProviderStatusChanged(providerType, connected, accountEmail);
            } catch (Exception e) {
                log.warn("Notification listener error: {}", e.getMessage());
            }
        }
    }

    public void publishSyncProgress(ProviderType providerType, String message, int newEmailsCount) {
        for (NotificationListener listener : listeners) {
            try {
                listener.onSyncProgress(providerType, message, newEmailsCount);
            } catch (Exception e) {
                log.warn("Notification listener error: {}", e.getMessage());
            }
        }
    }

    public List<SecurityAlert> getRecentAlerts() {
        return List.copyOf(recentAlerts);
    }
}
