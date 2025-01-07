package io.jhonathan.security.crypto;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * Gerador de chaves criptográficas.
 */
public class KeyGenerator {
    private final SecureRandom secureRandom;
    private SecretKey currentKey;
    private static final String ALGORITHM = "AES";

    public KeyGenerator() {
        this.secureRandom = new SecureRandom();
        this.currentKey = generateKey();
    }

    /**
     * Gera uma nova chave secreta AES.
     * @return Uma nova SecretKey para uso com AES
     */
    public SecretKey generateKey() {
        byte[] keyBytes = new byte[32];
        secureRandom.nextBytes(keyBytes);
        currentKey = new SecretKeySpec(keyBytes, ALGORITHM);
        return currentKey;
    }

    /**
     * Retorna a chave atual ou gera uma nova se não existir.
     * @return A SecretKey atual
     */
    public SecretKey getKey() {
        return currentKey != null ? currentKey : generateKey();
    }
}
