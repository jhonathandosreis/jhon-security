package io.jhonathan.security.behavioral;

import io.jhonathan.security.core.SecurityConfig;
import io.jhonathan.security.core.SecurityLevel;
import io.jhonathan.security.exception.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.*;

/**
 * Analisa padrões de comportamento para detectar atividades suspeitas.
 */
public class BehaviorAnalyzer {
    private final Map<String, UserProfile> profiles = new ConcurrentHashMap<>();
    private final SecurityConfig config;
    private final Logger logger = LoggerFactory.getLogger(BehaviorAnalyzer.class);
    private final ScheduledExecutorService scheduler;

    public BehaviorAnalyzer(SecurityConfig config) {
        if (config == null) {
            throw new SecurityException("Security configuration cannot be null");
        }
        this.config = config;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "behavior-analyzer-cleanup");
            thread.setDaemon(true);
            return thread;
        });

        startCleanupScheduler();
        logger.info("BehaviorAnalyzer initialized with security level: {}", config.getSecurityLevel());
    }

    /**
     * Inicia o agendador de limpeza de perfis
     */
    private void startCleanupScheduler() {
        scheduler.scheduleAtFixedRate(
                () -> {
                    try {
                        cleanupOldProfiles();
                    } catch (Exception e) {
                        logger.error("Failed to execute scheduled cleanup", e);
                    }
                },
                1,
                6,
                TimeUnit.HOURS
        );
    }

    /**
     * Analisa um evento de segurança e retorna um score de risco.
     *
     * @param event Evento a ser analisado
     * @return Score de risco entre 0.0 e 1.0
     * @throws SecurityException se ocorrer erro na análise
     */
    public double analyzeEvent(SecurityEvent event) {
        try {
            if (event == null) {
                throw new SecurityException("Security event cannot be null");
            }

            if (!config.isBehavioralAnalysis()) {
                return 0.0;
            }

            UserProfile profile = profiles.computeIfAbsent(
                    event.getUserId(),
                    id -> new UserProfile()
            );

            double riskScore = calculateRiskScore(event, profile);
            profile.updateWithEvent(event);

            logRiskAnalysis(event, riskScore);
            return adjustRiskScoreBySecurityLevel(riskScore);
        } catch (Exception e) {
            logger.error("Error analyzing security event", e);
            throw new SecurityException("Failed to analyze security event", e);
        }
    }

    private double calculateRiskScore(SecurityEvent event, UserProfile profile) {
        if (event == null || profile == null) {
            throw new SecurityException("Event and profile must not be null");
        }

        if (!profile.hasEvents() && config.getSecurityLevel() != SecurityLevel.EXTREME) {
            return 0.1;
        }

        double score = 0.0;
        int abnormalFactors = 0;

        if (!profile.isKnownLocation(event.getLocation())) {
            score += getLocationWeight();
            abnormalFactors++;
        }

        if (!profile.isUsualTime(event.getTimestamp())) {
            score += getTimeWeight();
            abnormalFactors++;
        }

        if (!profile.isKnownDevice(event.getDeviceFingerprint())) {
            score += getDeviceWeight();
            abnormalFactors++;
        }

        if (!profile.isNormalPattern(event.getActionType())) {
            score += getPatternWeight();
            abnormalFactors++;
        }

        if (profile.getTotalEvents() < 3 && config.getSecurityLevel() == SecurityLevel.EXTREME) {
            score += 0.2;
        }

        double multiplier = switch (abnormalFactors) {
            case 0 -> 0.5;
            case 1 -> 0.8;
            case 2 -> 1.2;
            case 3 -> 1.6;
            case 4 -> 2.0;
            default -> 1.0;
        };

        score *= multiplier;

        return Math.min(1.0, adjustRiskScoreBySecurityLevel(score));
    }

    private double getLocationWeight() {
        return switch (config.getSecurityLevel()) {
            case LOW -> 0.25;
            case MEDIUM -> 0.3;
            case HIGH -> 0.35;
            case EXTREME -> 0.4;
        };
    }

    private double getTimeWeight() {
        return switch (config.getSecurityLevel()) {
            case LOW -> 0.2;
            case MEDIUM -> 0.25;
            case HIGH -> 0.3;
            case EXTREME -> 0.35;
        };
    }

    private double getDeviceWeight() {
        return switch (config.getSecurityLevel()) {
            case LOW -> 0.25;
            case MEDIUM -> 0.3;
            case HIGH -> 0.35;
            case EXTREME -> 0.4;
        };
    }

    private double getPatternWeight() {
        return switch (config.getSecurityLevel()) {
            case LOW -> 0.2;
            case MEDIUM -> 0.25;
            case HIGH -> 0.3;
            case EXTREME -> 0.35;
        };
    }

    private double adjustRiskScoreBySecurityLevel(double riskScore) {
        return switch (config.getSecurityLevel()) {
            case LOW -> riskScore * 0.7;
            case MEDIUM -> riskScore * 0.9;
            case HIGH -> riskScore * 1.3;
            case EXTREME -> Math.min(1.0, riskScore * 2.0);
        };
    }

    private void logRiskAnalysis(SecurityEvent event, double riskScore) {
        if (riskScore > 0.7) {
            logger.warn("High risk score detected - User: {}, Score: {}, Location: {}",
                    event.getUserId(), riskScore, event.getLocation());
        } else {
            logger.debug("Risk score for user {}: {}", event.getUserId(), riskScore);
        }
    }

    /**
     * Limpa os perfis antigos que não são mais necessários.
     * @throws SecurityException se ocorrer erro na limpeza dos perfis
     */
    private void cleanupOldProfiles() {
        try {
            int sizeBefore = profiles.size();
            profiles.entrySet().removeIf(entry -> entry.getValue().isExpired());
            int removed = sizeBefore - profiles.size();

            if (removed > 0) {
                logger.info("Cleaned up {} expired profiles. Current size: {}",
                        removed, profiles.size());
            } else {
                logger.debug("No expired profiles found during cleanup");
            }
        } catch (Exception e) {
            logger.error("Failed to cleanup old profiles", e);
            throw new SecurityException("Failed to cleanup old profiles", e);
        }
    }

    /**
     * Finaliza o analisador comportamental e libera recursos.
     */
    public void shutdown() {
        try {
            scheduler.shutdown();
            if (!scheduler.awaitTermination(1, TimeUnit.MINUTES)) {
                scheduler.shutdownNow();
                logger.warn("Forced shutdown of behavior analyzer scheduler");
            }
            logger.info("BehaviorAnalyzer shutdown completed successfully");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.error("BehaviorAnalyzer shutdown interrupted", e);
        } catch (Exception e) {
            logger.error("Error during BehaviorAnalyzer shutdown", e);
            throw new SecurityException("Failed to shutdown BehaviorAnalyzer", e);
        }
    }
}
