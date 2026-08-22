package com.cipherdrop.exception;

import com.cipherdrop.dto.AccessSecretResponse;
import com.cipherdrop.dto.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Maps exceptions to the frozen status/reason table (architecture.md section 17).
 * Replaces the previous behavior of letting plain RuntimeExceptions bubble up
 * as generic 500s.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(SecretNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFound(SecretNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorResponse("NOT_FOUND"));
    }

    @ExceptionHandler(SecretExpiredException.class)
    public ResponseEntity<AccessSecretResponse> handleExpired(SecretExpiredException ex) {
        return ResponseEntity.status(HttpStatus.GONE).body(AccessSecretResponse.denied("EXPIRED"));
    }

    @ExceptionHandler(SecretConsumedException.class)
    public ResponseEntity<AccessSecretResponse> handleConsumed(SecretConsumedException ex) {
        return ResponseEntity.status(HttpStatus.GONE).body(AccessSecretResponse.denied("CONSUMED"));
    }

    @ExceptionHandler(ViewLimitReachedException.class)
    public ResponseEntity<AccessSecretResponse> handleViewLimitReached(ViewLimitReachedException ex) {
        return ResponseEntity.status(HttpStatus.GONE).body(AccessSecretResponse.denied("VIEW_LIMIT_REACHED"));
    }

    @ExceptionHandler(InvalidPasswordException.class)
    public ResponseEntity<AccessSecretResponse> handleInvalidPassword(InvalidPasswordException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(AccessSecretResponse.denied("INVALID_PASSWORD"));
    }

    @ExceptionHandler(InvalidManagementTokenException.class)
    public ResponseEntity<ErrorResponse> handleInvalidManagementToken(InvalidManagementTokenException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ErrorResponse("INVALID_MANAGEMENT_TOKEN"));
    }
}
