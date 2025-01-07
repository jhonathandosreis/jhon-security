package io.jhonathan.security.prevention;

import java.util.Map;

/**
 * Representa uma requisição para análise de segurança.
 */
public class SecurityRequest {
    private final String userId;
    private final String ipAddress;
    private final String userAgent;
    private final Map<String, String> headers;
    private final String requestPath;

    public SecurityRequest(String userId, String ipAddress, String userAgent, Map<String, String> headers, String requestPath) {
        this.userId = userId;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.headers = headers;
        this.requestPath = requestPath;
    }

    public String getUserId() {
        return userId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public String getRequestPath() {
        return requestPath;
    }
}
