package io.jhonathan.security.crypto;

import io.jhonathan.security.core.SecurityConfig;
import io.jhonathan.security.core.SecurityLevel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

class AdvancedEncryptionTest {
    private final SecurityConfig config = SecurityConfig.builder()
            .withSecurityLevel(SecurityLevel.HIGH)
            .withBehavioralAnalysis(true)
            .withAttackPrevention(true)
            .build();

    private final AdvancedEncryption encryption = new AdvancedEncryption(config);

    @Test
    @DisplayName("Deve criptografar e descriptografar dados corretamente")
    void shouldEncryptAndDecryptData() {
        String originalData = "Dados sensíveis para teste";
        String encrypted = encryption.encrypt(originalData);
        String decrypted = encryption.decrypt(encrypted);

        assertAll(
                () -> assertNotEquals(originalData, encrypted),
                () -> assertEquals(originalData, decrypted)
        );
    }

    @Test
    @DisplayName("Deve gerar diferentes criptografias para mesmos dados")
    void shouldGenerateDifferentEncryptionsForSameData() {
        String data = "Teste";
        String firstEncryption = encryption.encrypt(data);
        String secondEncryption = encryption.encrypt(data);

        assertNotEquals(firstEncryption, secondEncryption);
    }
}
