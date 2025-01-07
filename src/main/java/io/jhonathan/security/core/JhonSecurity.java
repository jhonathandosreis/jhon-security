package io.jhonathan.security.core;

import io.jhonathan.security.behavioral.BehaviorAnalyzer;
import io.jhonathan.security.crypto.AdvancedEncryption;
import io.jhonathan.security.prevention.AttackPreventor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Classe principal da biblioteca JhonSecurity.
 * Fornece uma interface unificada para todos os recursos de segurança.
 *
 * @author Jhonathan dos Reis
 * @version 1.0.0
 */
public class JhonSecurity {
    private final SecurityConfig config;
    private final AdvancedEncryption encryption;
    private final BehaviorAnalyzer behaviorAnalyzer;
    private final AttackPreventor attackPreventor;
    private final Logger logger = LoggerFactory.getLogger(JhonSecurity.class);

    /**
     * Construtor principal da biblioteca.
     *
     * @param config Configurações de segurança
     */
    public JhonSecurity(SecurityConfig config) {
        if (config == null) {
            throw new SecurityException("Security configuration cannot be null");
        }
        this.config = config;
        try {
            this.encryption = new AdvancedEncryption(config);
            this.behaviorAnalyzer = new BehaviorAnalyzer(config);
            this.attackPreventor = new AttackPreventor(config);
            logger.info("JhonSecurity initialized with security level: {}", config.getSecurityLevel());
        } catch (Exception e) {
            logger.error("Failed to initialize JhonSecurity", e);
            throw new SecurityException("Failed to initialize security components", e);
        }
    }

    /**
     * Cria uma nova instância usando o padrão builder.
     *
     * @return Builder para configurar a instância
     */
    public static Builder builder() {
        return new Builder();
    }

    public BehaviorAnalyzer getBehaviorAnalyzer() {
        return behaviorAnalyzer;
    }

    public AdvancedEncryption getEncryption() {
        return encryption;
    }

    public AttackPreventor getAttackPreventor() {
        return attackPreventor;
    }

    public SecurityConfig getConfig() {
        return config;
    }

    public static class Builder {
        private SecurityConfig.Builder configBuilder = SecurityConfig.builder();

        public Builder withSecurityLevel(SecurityLevel level) {
            configBuilder.withSecurityLevel(level);
            return this;
        }

        public Builder withBehavioralAnalysis(boolean enable) {
            configBuilder.withBehavioralAnalysis(enable);
            return this;
        }

        public Builder withAttackPrevention(boolean enable) {
            configBuilder.withAttackPrevention(enable);
            return this;
        }

        public JhonSecurity build() {
            return new JhonSecurity(configBuilder.build());
        }
    }
}
