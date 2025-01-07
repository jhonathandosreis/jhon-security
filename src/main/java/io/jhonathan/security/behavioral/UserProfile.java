package io.jhonathan.security.behavioral;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Representa um perfil de usuário com seus padrões comportamentais.
 */
public class UserProfile {
    private final Set<String> knownLocations = new HashSet<>();
    private final Set<String> knownDevices = new HashSet<>();
    private final Map<String, Integer> actionPatterns = new HashMap<>();
    private final List<LocalDateTime> accessTimes = new ArrayList<>();
    private LocalDateTime lastActivity = LocalDateTime.now();
    private static final Duration EXPIRATION_DURATION = Duration.ofDays(30);
    private int totalEvents = 0;

    public boolean hasEvents() {
        return !knownLocations.isEmpty() || !knownDevices.isEmpty() || !actionPatterns.isEmpty();
    }

    public int getTotalEvents() {
        return totalEvents;
    }

    public boolean isKnownLocation(String location) {
        return knownLocations.contains(location);
    }

    public boolean isKnownDevice(String deviceFingerprint) {
        return knownDevices.contains(deviceFingerprint);
    }

    public boolean isUsualTime(LocalDateTime timestamp) {
        if (accessTimes.isEmpty()) {
            return true;
        }

        int hour = timestamp.getHour();
        return accessTimes.stream()
                .map(LocalDateTime::getHour)
                .filter(h -> Math.abs(h - hour) <= 2)
                .count() > accessTimes.size() * 0.3;
    }

    public boolean isNormalPattern(String actionType) {
        if (actionPatterns.isEmpty()) {
            return true;
        }
        int count = actionPatterns.getOrDefault(actionType, 0);
        return count > 0;
    }

    public void updateWithEvent(SecurityEvent event) {
        knownLocations.add(event.getLocation());
        knownDevices.add(event.getDeviceFingerprint());
        actionPatterns.merge(event.getActionType(), 1, Integer::sum);
        accessTimes.add(event.getTimestamp());
        lastActivity = LocalDateTime.now();
        totalEvents++;

        if (accessTimes.size() > 100) {
            accessTimes.removeFirst();
        }
    }

    public boolean isExpired() {
        return lastActivity.plus(EXPIRATION_DURATION).isBefore(LocalDateTime.now());
    }
}
