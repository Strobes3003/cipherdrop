package com.cipherdrop.exception;

/** Thrown when a secret's expiresAt has passed. Maps to 410 EXPIRED. */
public class SecretExpiredException extends RuntimeException {
    public SecretExpiredException(String id) {
        super("Secret expired: " + id);
    }
}
