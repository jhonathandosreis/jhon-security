package io.jhonathan.security.exception;

/**
 * Exceção base para erros de segurança.
 */
public class SecurityException extends RuntimeException {
    public SecurityException(String message) {
        super(message);
    }

    public SecurityException(String message, Throwable cause) {
        super(message, cause);
    }
}
