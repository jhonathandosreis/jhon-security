package io.jhonathan.security.core;

import java.time.Duration;
import java.util.Objects;

/**
 * Configuração central da biblioteca JhonSecurity.
 * Define todos os parâmetros de configuração para os diferentes módulos de segurança.
 */
public class SecurityConfig {
    private final SecurityLevel securityLevel;
    private final boolean behavioralAnalysis;
    private final boolean attackPrevention;
    private final int maxLoginAttempts;
    private final Duration lockoutDuration;
    private final int maxRequestsPerMinute;

    public SecurityConfig(Builder builder) {
        this.securityLevel = Objects.requireNonNull(builder.securityLevel, "securityLevel cannot be null");
        this.behavioralAnalysis = builder.behavioralAnalysis;
        this.attackPrevention = builder.attackPrevention;
        this.maxLoginAttempts = builder.maxLoginAttempts;
        this.lockoutDuration = Objects.requireNonNullElse(builder.lockoutDuration, Duration.ofMinutes(30));
        this.maxRequestsPerMinute = builder.maxRequestsPerMinute;
    }

    public SecurityLevel getSecurityLevel() {
        return securityLevel;
    }

    public boolean isBehavioralAnalysis() {
        return behavioralAnalysis;
    }

    public boolean isAttackPrevention() {
        return attackPrevention;
    }

    public int getMaxLoginAttempts() {
        return maxLoginAttempts;
    }

    public Duration getLockoutDuration() {
        return lockoutDuration;
    }

    public int getMaxRequestsPerMinute() {
        return maxRequestsPerMinute;
    }

    /**
     * Cria um novo builder para SecurityConfig.
     * @return Uma nova instância do Builder
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private SecurityLevel securityLevel = SecurityLevel.HIGH;
        private boolean behavioralAnalysis = true;
        private boolean attackPrevention = true;
        private int maxLoginAttempts = 5;
        private Duration lockoutDuration = Duration.ofMinutes(30);
        private int maxRequestsPerMinute = 100;

        private Builder() {
        }

        public Builder withSecurityLevel(SecurityLevel securityLevel) {
            this.securityLevel = securityLevel;
            return this;
        }

        public Builder withBehavioralAnalysis(boolean behavioralAnalysis) {
            this.behavioralAnalysis = behavioralAnalysis;
            return this;
        }

        public Builder withAttackPrevention(boolean attackPrevention) {
            this.attackPrevention = attackPrevention;
            return this;
        }

        public Builder withMaxLoginAttempts(int maxLoginAttempts) {
            this.maxLoginAttempts = maxLoginAttempts;
            return this;
        }

        public Builder withLockoutDuration(Duration lockoutDuration) {
            this.lockoutDuration = lockoutDuration;
            return this;
        }

        public Builder withMaxRequestsPerMinute(int maxRequestsPerMinute) {
            this.maxRequestsPerMinute = maxRequestsPerMinute;
            return this;
        }

        public SecurityConfig build() {
            return new SecurityConfig(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityConfig that = (SecurityConfig) o;
        return behavioralAnalysis == that.behavioralAnalysis &&
                attackPrevention == that.attackPrevention &&
                maxLoginAttempts == that.maxLoginAttempts &&
                maxRequestsPerMinute == that.maxRequestsPerMinute &&
                securityLevel == that.securityLevel &&
                Objects.equals(lockoutDuration, that.lockoutDuration);
    }

    @Override
    public int hashCode() {
        return Objects.hash(securityLevel, behavioralAnalysis, attackPrevention,
                maxLoginAttempts, lockoutDuration, maxRequestsPerMinute);
    }

    @Override
    public String toString() {
        return "SecurityConfig{" +
                "securityLevel=" + securityLevel +
                ", behavioralAnalysis=" + behavioralAnalysis +
                ", attackPrevention=" + attackPrevention +
                ", maxLoginAttempts=" + maxLoginAttempts +
                ", lockoutDuration=" + lockoutDuration +
                ", maxRequestsPerMinute=" + maxRequestsPerMinute +
                '}';
    }
}
