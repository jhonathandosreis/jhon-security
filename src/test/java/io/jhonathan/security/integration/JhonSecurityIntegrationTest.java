package io.jhonathan.security.integration;

import io.jhonathan.security.behavioral.SecurityEvent;
import io.jhonathan.security.core.JhonSecurity;
import io.jhonathan.security.core.SecurityLevel;
import io.jhonathan.security.prevention.SecurityRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JhonSecurityIntegrationTest {
    private JhonSecurity securityLow;
    private JhonSecurity securityExtreme;

    @BeforeEach
    void setUp() {
        securityLow = JhonSecurity.builder()
                .withSecurityLevel(SecurityLevel.LOW)
                .withBehavioralAnalysis(true)
                .withAttackPrevention(true)
                .build();

        securityExtreme = JhonSecurity.builder()
                .withSecurityLevel(SecurityLevel.EXTREME)
                .withBehavioralAnalysis(true)
                .withAttackPrevention(true)
                .build();
    }

    @Test
    @DisplayName("Deve integrar todos os componentes corretamente")
    void shouldIntegrateAllComponents() {
        String userId = "integration-test-user";

        SecurityEvent normalEvent = SecurityEvent.builder()
                .userId(userId)
                .location("127.0.0.1")
                .actionType("LOGIN")
                .deviceFingerprint("test-device")
                .build();

        double score = securityLow.getBehaviorAnalyzer().analyzeEvent(normalEvent);
        assertTrue(score < 0.5, "Score para comportamento normal deve ser baixo");

        SecurityEvent suspiciousEvent = SecurityEvent.builder()
                .userId(userId)
                .location("unknown-location")
                .actionType("SENSITIVE_ACCESS")
                .deviceFingerprint("unknown-device")
                .build();

        double suspiciousScore = securityExtreme.getBehaviorAnalyzer().analyzeEvent(suspiciousEvent);
        assertTrue(suspiciousScore > 0.5, "Score para comportamento suspeito deve ser alto");
    }

    @Test
    @DisplayName("Deve executar fluxo completo de segurança")
    void shouldExecuteFullSecurityFlow() {
        String userId = "test-user";
        String ipAddress = "127.0.0.1";
        String sensitiveData = "dados confidenciais";

        String encrypted = securityLow.getEncryption().encrypt(sensitiveData);

        SecurityEvent event = SecurityEvent.builder()
                .userId(userId)
                .location(ipAddress)
                .actionType("DATA_ACCESS")
                .deviceFingerprint("test-device")
                .build();

        double riskScore = securityLow.getBehaviorAnalyzer().analyzeEvent(event);

        SecurityRequest request = new SecurityRequest(
                userId,
                ipAddress,
                "Mozilla/5.0",
                Map.of(
                        "Accept", "application/json",
                        "User-Agent", "Mozilla/5.0",
                        "Host", "example.com"
                ),
                "/api/data"
        );

        boolean blocked = securityLow.getAttackPreventor().shouldBlock(request);

        assertAll(
                () -> assertNotEquals(sensitiveData, encrypted),
                () -> assertEquals(sensitiveData, securityLow.getEncryption().decrypt(encrypted)),
                () -> assertTrue(riskScore >= 0.0 && riskScore < 0.5),
                () -> assertFalse(blocked)
        );
    }
}