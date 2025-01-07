package io.jhonathan.security.behavioral;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Representa um evento de segurança para análise comportamental.
 * Esta classe é imutável e thread-safe.
 */
public class SecurityEvent {
    private final String userId;
    private final String location;
    private final String deviceFingerprint;
    private final String actionType;
    private final LocalDateTime timestamp;

    private SecurityEvent(Builder builder) {
        this.userId = Objects.requireNonNull(builder.userId, "userId cannot be null");
        this.location = Objects.requireNonNull(builder.location, "location cannot be null");
        this.deviceFingerprint = builder.deviceFingerprint;
        this.actionType = Objects.requireNonNull(builder.actionType, "actionType cannot be null");
        this.timestamp = Objects.requireNonNullElseGet(builder.timestamp, LocalDateTime::now);
    }

    public String getUserId() {
        return userId;
    }

    public String getLocation() {
        return location;
    }

    public String getDeviceFingerprint() {
        return deviceFingerprint;
    }

    public String getActionType() {
        return actionType;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String userId;
        private String location;
        private String deviceFingerprint;
        private String actionType;
        private LocalDateTime timestamp;

        private Builder() {
        }

        public Builder userId(String userId) {
            this.userId = userId;
            return this;
        }

        public Builder location(String location) {
            this.location = location;
            return this;
        }

        public Builder deviceFingerprint(String deviceFingerprint) {
            this.deviceFingerprint = deviceFingerprint;
            return this;
        }

        public Builder actionType(String actionType) {
            this.actionType = actionType;
            return this;
        }

        public Builder timestamp(LocalDateTime timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public SecurityEvent build() {
            return new SecurityEvent(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityEvent that = (SecurityEvent) o;
        return Objects.equals(userId, that.userId) &&
                Objects.equals(location, that.location) &&
                Objects.equals(deviceFingerprint, that.deviceFingerprint) &&
                Objects.equals(actionType, that.actionType) &&
                Objects.equals(timestamp, that.timestamp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, location, deviceFingerprint, actionType, timestamp);
    }

    @Override
    public String toString() {
        return "SecurityEvent{" +
                "userId='" + userId + '\'' +
                ", location='" + location + '\'' +
                ", deviceFingerprint='" + deviceFingerprint + '\'' +
                ", actionType='" + actionType + '\'' +
                ", timestamp=" + timestamp +
                '}';
    }
}
