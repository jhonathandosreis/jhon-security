package io.jhonathan.security.core;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

class JhonSecurityTest {
    private JhonSecurity security;

    @BeforeEach
    void setUp() {
        security = JhonSecurity.builder()
                .withSecurityLevel(SecurityLevel.HIGH)
                .withBehavioralAnalysis(true)
                .withAttackPrevention(true)
                .build();
    }

    @Test
    @DisplayName("Deve inicializar com configurações padrão")
    void shouldInitializeWithDefaultConfig() {
        assertNotNull(security);
    }

    @Test
    @DisplayName("Deve configurar nível de segurança corretamente")
    void shouldConfigureSecurityLevel() {
        JhonSecurity customSecurity = JhonSecurity.builder()
                .withSecurityLevel(SecurityLevel.EXTREME)
                .build();

        assertEquals(SecurityLevel.EXTREME, customSecurity.getConfig().getSecurityLevel());
    }
}
