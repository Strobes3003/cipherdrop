package com.cipherdrop.exception;

/** Thrown when a burn-after-reading secret has already been consumed. Maps to 410 CONSUMED. */
public class SecretConsumedException extends RuntimeException {
    public SecretConsumedException(String id) {
        super("Secret already consumed: " + id);
    }
}
