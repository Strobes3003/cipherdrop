package com.cipherdrop.exception;

/** Thrown when a secret id does not exist (or is soft-deleted). Maps to 404 NOT_FOUND. */
public class SecretNotFoundException extends RuntimeException {
    public SecretNotFoundException(String id) {
        super("Secret not found: " + id);
    }
}
