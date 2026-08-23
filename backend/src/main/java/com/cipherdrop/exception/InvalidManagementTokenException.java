package com.cipherdrop.exception;

/** Thrown when the Bearer management token doesn't match management_token_hash. Maps to 403 INVALID_MANAGEMENT_TOKEN. */
public class InvalidManagementTokenException extends RuntimeException {
    public InvalidManagementTokenException(String id) {
        super("Invalid management token for secret: " + id);
    }
}
