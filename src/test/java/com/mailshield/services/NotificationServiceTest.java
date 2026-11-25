package com.mailshield.services;

import com.mailshield.model.ProviderType;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class NotificationServiceTest {

    @Test
    void shouldDispatchSecurityAlertsToRegisteredListeners() {
        NotificationService service = new NotificationService();
        AtomicBoolean alertReceived = new AtomicBoolean(false);

        service.addListener(new NotificationService.NotificationListener() {
            @Override
            public void onSecurityAlert(NotificationService.SecurityAlert alert) {
                if ("CRITICAL".equals(alert.severity()) && alert.title().contains("Phishing")) {
                    alertReceived.set(true);
                }
            }

            @Override
            public void onProviderStatusChanged(ProviderType providerType, boolean connected, String accountEmail) {}

            @Override
            public void onSyncProgress(ProviderType providerType, String message, int newEmailsCount) {}
        });

        service.publishAlert("Phishing Threat Detected", "Malicious attachment found", "CRITICAL", "msg-101");
        assertThat(alertReceived.get()).isTrue();
        assertThat(service.getRecentAlerts()).hasSize(1);
    }

    @Test
    void shouldDispatchProviderStatusAndSyncEvents() {
        NotificationService service = new NotificationService();
        AtomicBoolean providerEvent = new AtomicBoolean(false);
        AtomicInteger syncEmailCount = new AtomicInteger(-1);

        service.addListener(new NotificationService.NotificationListener() {
            @Override
            public void onSecurityAlert(NotificationService.SecurityAlert alert) {}

            @Override
            public void onProviderStatusChanged(ProviderType providerType, boolean connected, String accountEmail) {
                if (providerType == ProviderType.GMAIL && connected) {
                    providerEvent.set(true);
                }
            }

            @Override
            public void onSyncProgress(ProviderType providerType, String message, int newEmailsCount) {
                syncEmailCount.set(newEmailsCount);
            }
        });

        service.publishProviderStatus(ProviderType.GMAIL, true, "analyst@mailshield.io");
        service.publishSyncProgress(ProviderType.GMAIL, "Sync complete", 14);

        assertThat(providerEvent.get()).isTrue();
        assertThat(syncEmailCount.get()).isEqualTo(14);
    }
}
