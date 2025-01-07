package io.jhonathan.security.crypto;

import io.jhonathan.security.core.SecurityConfig;
import io.jhonathan.security.exception.SecurityException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

/**
 * Implementa criptografia avançada com suporte a algoritmos modernos.
 */
public class AdvancedEncryption {
    private final SecurityConfig config;
    private final KeyGenerator keyGenerator;
    private final Logger logger = LoggerFactory.getLogger(AdvancedEncryption.class);

    public AdvancedEncryption(SecurityConfig config) {
        if (config == null) {
            throw new SecurityException("Security configuration cannot be null");
        }
        this.config = config;
        this.keyGenerator = new KeyGenerator();
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Criptografa dados usando algoritmos modernos.
     *
     * @param data Dados a serem criptografados
     * @return Dados criptografados em Base64
     * @throws SecurityException se ocorrer erro na criptografia
     */
    public String encrypt(String data) {
        if (data == null || data.isEmpty()) {
            throw new SecurityException("Data to encrypt cannot be null or empty");
        }

        try {
            SecretKey key = keyGenerator.generateKey();

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            byte[] iv = generateIV();
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);

            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encrypted.length);
            byteBuffer.put(iv);
            byteBuffer.put(encrypted);

            return Base64.getEncoder().encodeToString(byteBuffer.array());
        } catch (Exception e) {
            logger.error("Encryption failed", e);
            throw new SecurityException("Failed to encrypt data", e);
        }
    }

    /**
     * Descriptografa dados.
     *
     * @param encryptedData Dados criptografados em Base64
     * @return Dados descriptografados
     * @throws SecurityException se ocorrer erro na descriptografia
     */
    public String decrypt(String encryptedData) {
        if (encryptedData == null || encryptedData.isEmpty()) {
            throw new SecurityException("Encrypted data cannot be null or empty");
        }

        try {
            byte[] decoded = Base64.getDecoder().decode(encryptedData);
            ByteBuffer byteBuffer = ByteBuffer.wrap(decoded);

            byte[] iv = new byte[12];
            byteBuffer.get(iv);

            byte[] cipherText = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherText);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            SecretKey key = keyGenerator.getKey();
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);

            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            byte[] decrypted = cipher.doFinal(cipherText);

            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.error("Decryption failed", e);
            throw new SecurityException("Failed to decrypt data", e);
        }
    }

    private byte[] generateIV() {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
