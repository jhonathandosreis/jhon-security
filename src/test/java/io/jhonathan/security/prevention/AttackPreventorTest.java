package io.jhonathan.security.prevention;

import io.jhonathan.security.core.SecurityConfig;
import io.jhonathan.security.core.SecurityLevel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AttackPreventorTest {
    private final SecurityConfig config = SecurityConfig.builder()
            .withSecurityLevel(SecurityLevel.HIGH)
            .withAttackPrevention(true)
            .withMaxLoginAttempts(3)
            .withLockoutDuration(Duration.ofMinutes(15))
            .withMaxRequestsPerMinute(50)
            .build();

    private final AttackPreventor preventor = new AttackPreventor(config);

    @Test
    @DisplayName("Deve bloquear tentativas excessivas de login")
    void shouldBlockExcessiveLoginAttempts() {
        String ipAddress = "192.168.1.1";
        SecurityRequest request = new SecurityRequest(
                "user123",
                ipAddress,
                "test-agent",
                Map.of(),
                "/login"
        );

        assertFalse(preventor.shouldBlock(request), "Primeira tentativa não deve ser bloqueada");
        assertFalse(preventor.shouldBlock(request), "Segunda tentativa não deve ser bloqueada");
        assertFalse(preventor.shouldBlock(request), "Terceira tentativa não deve ser bloqueada");
        assertTrue(preventor.shouldBlock(request), "Quarta tentativa deve ser bloqueada");
    }

    @Test
    @DisplayName("Deve detectar ataque de força bruta")
    void shouldDetectBruteForceAttack() {
        String ipAddress = "192.168.1.2";

        for (int i = 0; i < 10; i++) {
            SecurityRequest request = new SecurityRequest(
                    "user" + i,
                    ipAddress,
                    "test-agent",
                    Map.of(),
                    "/login"
            );
            preventor.shouldBlock(request);
        }

        SecurityRequest newRequest = new SecurityRequest(
                "user123",
                ipAddress,
                "test-agent",
                Map.of(),
                "/login"
        );

        assertTrue(preventor.shouldBlock(newRequest), "Deve bloquear após múltiplas tentativas de diferentes usuários");
    }

    @Test
    @DisplayName("Deve detectar padrões suspeitos nos headers")
    void shouldDetectSuspiciousHeaders() {
        SecurityRequest request = new SecurityRequest(
                "user123",
                "192.168.1.3",
                "test-agent",
                Map.of(
                        "X-Forwarded-For", "' OR '1'='1",
                        "User-Agent", "<script>alert('xss')</script>"
                ),
                "/api/data"
        );

        assertTrue(preventor.shouldBlock(request), "Deve bloquear requisição com headers suspeitos");
    }

    @Test
    @DisplayName("Deve permitir requisições normais")
    void shouldAllowNormalRequests() {
        SecurityRequest request = new SecurityRequest(
                "user123",
                "192.168.1.4",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                Map.of(
                        "Accept", "application/json",
                        "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                        "Host", "example.com"
                ),
                "/api/data"
        );

        assertFalse(preventor.shouldBlock(request), "Deve permitir requisições com padrão normal");
    }
}
