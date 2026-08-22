package com.cipherdrop.exception;

/** Thrown when a supplied password does not match the stored hash. Maps to 403 INVALID_PASSWORD. */
public class InvalidPasswordException extends RuntimeException {
    public InvalidPasswordException(String id) {
        super("Invalid password for secret: " + id);
    }
}
