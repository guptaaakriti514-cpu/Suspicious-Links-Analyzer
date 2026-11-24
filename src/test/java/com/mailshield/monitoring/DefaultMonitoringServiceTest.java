package com.mailshield.monitoring;

import com.mailshield.detection.DetectionEngine;
import com.mailshield.detection.SafeAttachmentAnalyzer;
import com.mailshield.detection.SafeContentAnalyzer;
import com.mailshield.detection.SafeHeaderAnalyzer;
import com.mailshield.detection.SafeUrlAnalyzer;
import com.mailshield.forensics.DefaultEvidenceManager;
import com.mailshield.forensics.EvidenceManager;
import com.mailshield.intelligence.LocalThreatIntelligenceService;
import com.mailshield.model.EmailMessage;
import com.mailshield.model.ProviderConnectionStatus;
import com.mailshield.model.ProviderType;
import com.mailshield.providers.EmailProvider;
import com.mailshield.providers.ProviderException;
import com.mailshield.scoring.DefaultRiskScoringEngine;
import com.mailshield.storage.CaseRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultMonitoringServiceTest {

    private DetectionEngine detectionEngine;
    private EvidenceManager evidenceManager;

    @BeforeEach
    void setUp() {
        var urlAnalyzer = new SafeUrlAnalyzer();
        detectionEngine = new DetectionEngine(
                new SafeHeaderAnalyzer(),
                new SafeContentAnalyzer(),
                urlAnalyzer,
                new SafeAttachmentAnalyzer(),
                new LocalThreatIntelligenceService(null),
                new DefaultRiskScoringEngine()
        );
        evidenceManager = new DefaultEvidenceManager(null);
    }

    @Test
    void testHasAnyConnectedProviderFalseWhenDisconnected() {
        Map<ProviderType, EmailProvider> providers = new EnumMap<>(ProviderType.class);
        EmailProvider mockProvider = createMockProvider(false, List.of());
        providers.put(ProviderType.GMAIL, mockProvider);

        DefaultMonitoringService service = new DefaultMonitoringService(
                providers, detectionEngine, null, evidenceManager
        );

        assertThat(service.hasAnyConnectedProvider()).isFalse();
        assertThat(service.triggerSyncAllConnected(10)).isEqualTo(0);
    }

    @Test
    void testHasAnyConnectedProviderTrueAndSyncsEmails() {
        EmailMessage sampleEmail = EmailMessage.builder()
                .id("test-msg-01")
                .providerMessageId("prov-01")
                .providerSource(ProviderType.GMAIL)
                .fromAddress("sender@example.com")
                .from("Sender <sender@example.com>")
                .subject("Routine Update")
                .bodyText("Here is the monthly report.")
                .bodyHtml("<p>Here is the monthly report.</p>")
                .ingestedAt(Instant.now())
                .rawSha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .build();

        Map<ProviderType, EmailProvider> providers = new EnumMap<>(ProviderType.class);
        EmailProvider mockProvider = createMockProvider(true, List.of(sampleEmail));
        providers.put(ProviderType.GMAIL, mockProvider);

        DefaultMonitoringService service = new DefaultMonitoringService(
                providers, detectionEngine, null, evidenceManager
        );

        assertThat(service.hasAnyConnectedProvider()).isTrue();
        int synced = service.triggerSyncAllConnected(10);
        assertThat(synced).isEqualTo(1);
    }

    private EmailProvider createMockProvider(boolean connected, List<EmailMessage> messagesToReturn) {
        return new EmailProvider() {
            @Override
            public ProviderType getProviderType() {
                return ProviderType.GMAIL;
            }

            @Override
            public ProviderConnectionStatus getStatus() {
                return new ProviderConnectionStatus(
                        ProviderType.GMAIL, connected, connected ? "user@example.com" : "",
                        Instant.now(), connected ? "Connected" : "Disconnected", "", List.of(), true
                );
            }

            @Override
            public boolean testConnection() {
                return connected;
            }

            @Override
            public boolean authenticate() {
                return connected;
            }

            @Override
            public void disconnect() {}

            @Override
            public List<EmailMessage> fetchRecentMessages(int maxMessages) throws ProviderException {
                return messagesToReturn;
            }
        };
    }
}
