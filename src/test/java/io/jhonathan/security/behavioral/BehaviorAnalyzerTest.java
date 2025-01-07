package io.jhonathan.security.behavioral;

import io.jhonathan.security.core.SecurityConfig;
import io.jhonathan.security.core.SecurityLevel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

class BehaviorAnalyzerTest {
    private final SecurityConfig config = SecurityConfig.builder()
            .withSecurityLevel(SecurityLevel.HIGH)
            .withBehavioralAnalysis(true)
            .withAttackPrevention(true)
            .withMaxLoginAttempts(5)
            .withMaxRequestsPerMinute(100)
            .build();

    private final BehaviorAnalyzer analyzer = new BehaviorAnalyzer(config);

    @Test
    @DisplayName("Deve identificar comportamento normal")
    void shouldIdentifyNormalBehavior() {
        SecurityEvent event = SecurityEvent.builder()
                .userId("user123")
                .location("127.0.0.1")
                .actionType("LOGIN")
                .deviceFingerprint("device-123")
                .build();

        double riskScore = analyzer.analyzeEvent(event);
        assertTrue(riskScore < 0.5, "Comportamento normal deve ter score menor que 0.5");
    }

    @Test
    @DisplayName("Deve identificar comportamento suspeito")
    void shouldIdentifySuspiciousBehavior() {
        SecurityEvent normalEvent = SecurityEvent.builder()
                .userId("user123")
                .location("127.0.0.1")
                .actionType("LOGIN")
                .deviceFingerprint("device-123")
                .build();

        analyzer.analyzeEvent(normalEvent);

        SecurityEvent suspiciousEvent = SecurityEvent.builder()
                .userId("user123")
                .location("suspicious.ip.address")
                .actionType("LOGIN")
                .deviceFingerprint("unknown-device")
                .build();

        double riskScore = analyzer.analyzeEvent(suspiciousEvent);
        assertTrue(riskScore >= 0.5, "Comportamento suspeito deve ter score maior ou igual a 0.5");
    }

    @Test
    @DisplayName("Deve retornar score zero quando análise comportamental está desativada")
    void shouldReturnZeroScoreWhenBehavioralAnalysisIsDisabled() {
        SecurityConfig disabledConfig = SecurityConfig.builder()
                .withSecurityLevel(SecurityLevel.LOW)
                .withBehavioralAnalysis(false)
                .build();

        BehaviorAnalyzer disabledAnalyzer = new BehaviorAnalyzer(disabledConfig);

        SecurityEvent event = SecurityEvent.builder()
                .userId("user123")
                .location("127.0.0.1")
                .actionType("LOGIN")
                .deviceFingerprint("device-123")
                .build();

        double riskScore = disabledAnalyzer.analyzeEvent(event);
        assertEquals(0.0, riskScore, "Score deve ser zero quando análise comportamental está desativada");
    }

    @Test
    @DisplayName("Deve ajustar score baseado no nível de segurança")
    void shouldAdjustScoreBasedOnSecurityLevel() {
        SecurityConfig extremeConfig = SecurityConfig.builder()
                .withSecurityLevel(SecurityLevel.EXTREME)
                .withBehavioralAnalysis(true)
                .build();

        BehaviorAnalyzer extremeAnalyzer = new BehaviorAnalyzer(extremeConfig);

        SecurityEvent suspiciousEvent = SecurityEvent.builder()
                .userId("user123")
                .location("suspicious.ip.address")
                .actionType("SENSITIVE_ACTION")
                .deviceFingerprint("unknown-device")
                .build();

        double riskScore = extremeAnalyzer.analyzeEvent(suspiciousEvent);
        assertTrue(riskScore > 0.7, "Score deve ser mais alto em nível de segurança EXTREME");
    }
}
