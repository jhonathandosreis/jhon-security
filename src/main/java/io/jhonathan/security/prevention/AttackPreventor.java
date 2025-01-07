package io.jhonathan.security.prevention;

import io.jhonathan.security.behavioral.SecurityEvent;
import io.jhonathan.security.core.SecurityConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Sistema de prevenção de ataques em tempo real.
 */
public class AttackPreventor {
    private final RateLimiter rateLimiter;
    private final Map<String, List<SecurityEvent>> eventLog;
    private final SecurityConfig config;
    private final Logger logger = LoggerFactory.getLogger(AttackPreventor.class);

    public AttackPreventor(SecurityConfig config) {
        if (config == null) {
            throw new SecurityException("Security configuration cannot be null");
        }
        this.config = config;
        this.rateLimiter = new RateLimiter(config);
        this.eventLog = new ConcurrentHashMap<>();
    }

    /**
     * Verifica se uma requisição deve ser bloqueada.
     *
     * @param request Detalhes da requisição
     * @return true se a requisição deve ser bloqueada
     * @throws SecurityException se ocorrer erro na verificação
     */
    public boolean shouldBlock(SecurityRequest request) {
        try {
            if (request == null) {
                throw new SecurityException("Security request cannot be null");
            }

            if (request.getIpAddress() == null || request.getIpAddress().isEmpty()) {
                throw new SecurityException("IP address cannot be null or empty");
            }

            if (rateLimiter.isRateLimited(request.getIpAddress())) {
                logger.warn("Rate limit exceeded for IP: {}", request.getIpAddress());
                return true;
            }

            if (detectBruteForce(request)) {
                logger.warn("Brute force attack detected from IP: {}", request.getIpAddress());
                return true;
            }

            if (detectSuspiciousPattern(request)) {
                logger.warn("Suspicious pattern detected from IP: {}", request.getIpAddress());
                return true;
            }

            return false;
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Error processing security request", e);
            throw new SecurityException("Failed to process security request", e);
        }
    }

    private boolean detectBruteForce(SecurityRequest request) {
        try {
            List<SecurityEvent> events = eventLog.computeIfAbsent(
                    request.getIpAddress(),
                    k -> new ArrayList<>()
            );

            events.removeIf(e ->
                    e.getTimestamp().isBefore(LocalDateTime.now().minusMinutes(30))
            );

            events.add(SecurityEvent.builder()
                    .userId(request.getUserId())
                    .location(request.getIpAddress())
                    .actionType("LOGIN_ATTEMPT")
                    .build());

            return events.size() > config.getMaxLoginAttempts();
        } catch (Exception e) {
            logger.error("Error detecting brute force", e);
            return false;
        }
    }

    private boolean detectSuspiciousPattern(SecurityRequest request) {
        if (isIpInSuspiciousList(request.getIpAddress())) {
            logger.warn("IP {} is in suspicious list", request.getIpAddress());
            return true;
        }

        if (request.getHeaders() != null && !request.getHeaders().isEmpty()) {
            if (isHeaderSuspicious(request.getHeaders())) {
                return true;
            }
        }

        if (request.getUserAgent() != null && !request.getUserAgent().trim().isEmpty()) {
            if (hasMailiciousPatternInUserAgent(request.getUserAgent())) {
                return true;
            }
        }

        if (request.getRequestPath() != null && !request.getRequestPath().trim().isEmpty()) {
            if (hasMailiciousPatternInPath(request.getRequestPath())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Verifica se os headers contêm padrões suspeitos ou estão ausentes quando deveriam estar presentes
     */
    private boolean isHeaderSuspicious(Map<String, String> headers) {
        List<String> requiredHeaders = Arrays.asList(
                "User-Agent",
                "Accept",
                "Host"
        );

        boolean hasMissingHeaders = requiredHeaders.stream()
                .anyMatch(header -> !headers.containsKey(header) ||
                        headers.get(header) == null ||
                        headers.get(header).trim().isEmpty());

        if (hasMissingHeaders) {
            return true;
        }

        List<Pattern> suspiciousPatterns = Arrays.asList(
                Pattern.compile("(?i).*(<script|alert\\(|eval\\(|javascript:).*"),
                Pattern.compile("(?i).*(union\\s+select|select.*from|insert\\s+into|delete\\s+from).*"),
                Pattern.compile("(?i).*(../../|%2e%2e%2f|%252e%252e%252f).*")
        );

        return headers.values().stream()
                .anyMatch(value -> suspiciousPatterns.stream()
                        .anyMatch(pattern -> pattern.matcher(value).matches()));
    }

    /**
     * Verifica padrões maliciosos no User-Agent
     */
    private boolean hasMailiciousPatternInUserAgent(String userAgent) {
        if (userAgent == null || userAgent.trim().isEmpty()) {
            return true;
        }

        List<Pattern> suspiciousPatterns = Arrays.asList(
                Pattern.compile("(?i).*(curl|wget|postman|insomnia).*"),
                Pattern.compile("(?i).*(nikto|sqlmap|nmap|burpsuite).*"),
                Pattern.compile("(?i).*(python-requests|go-http-client|ruby).*")
        );

        return suspiciousPatterns.stream()
                .anyMatch(pattern -> pattern.matcher(userAgent).matches());
    }

    /**
     * Verifica padrões maliciosos no path da requisição
     */
    private boolean hasMailiciousPatternInPath(String path) {
        if (path == null) {
            return true;
        }

        List<Pattern> suspiciousPatterns = Arrays.asList(
                Pattern.compile("(?i).*(union\\s+select|select.*from|insert\\s+into|delete\\s+from).*"),

                Pattern.compile("(?i).*(../../|%2e%2e%2f|%252e%252e%252f).*"),

                Pattern.compile("(?i).*(;\\s*[a-z]+|\\|\\s*[a-z]+|`.*`|\\$\\(.*\\)).*"),

                Pattern.compile("(?i).*(\\.(php|asp|jsp|cgi|config|ini|env)).*"),

                Pattern.compile("(?i).*(<script|alert\\(|eval\\(|javascript:).*")
        );

        return suspiciousPatterns.stream()
                .anyMatch(pattern -> pattern.matcher(path).matches());
    }

    /**
     * Verifica se o IP está em uma lista de IPs suspeitos
     * Em uma implementação real, isso poderia consultar uma base de dados ou serviço externo
     */
    private boolean isIpInSuspiciousList(String ipAddress) {
        if (ipAddress == null || ipAddress.isEmpty()) {
            return true;
        }

        try {
            String[] parts = ipAddress.split("\\.");
            if (parts.length != 4) {
                return true;
            }

            for (String part : parts) {
                int value = Integer.parseInt(part);
                if (value < 0 || value > 255) {
                    return true;
                }
            }

            return false;
        } catch (NumberFormatException e) {
            return true;
        }
    }
}
