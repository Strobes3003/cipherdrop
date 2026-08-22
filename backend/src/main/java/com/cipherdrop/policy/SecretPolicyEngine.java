package com.cipherdrop.policy;

import com.cipherdrop.entity.Secret;
import com.cipherdrop.enums.SecretStatus;
import com.cipherdrop.exception.InvalidPasswordException;
import com.cipherdrop.exception.SecretConsumedException;
import com.cipherdrop.exception.SecretExpiredException;
import com.cipherdrop.exception.SecretNotFoundException;
import com.cipherdrop.exception.ViewLimitReachedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * SecretPolicyEngine — "should this request receive the encrypted content?"
 *
 * Pure decision logic: never touches the repository, never mutates the
 * secret. SecretService applies the consequences (incrementing views,
 * flipping status) after a validateAccess() call returns normally.
 */
@Component
public class SecretPolicyEngine {

    /**
     * Read-only status resolution for GET /api/secrets/{id}.
     * Returns a plain access-state string; never throws for "unavailable"
     * states since GET returns 200 with an access field, not an error -
     * except DELETED, which is treated as gone (caller should 404 before
     * ever calling this with a deleted secret, but we guard here too).
     */
    public String resolveAccessState(Secret secret, Instant now) {
        if (secret.getStatus() == SecretStatus.DELETED) {
            throw new SecretNotFoundException(secret.getId());
        }
        if (secret.getStatus() == SecretStatus.CONSUMED) {
            return "CONSUMED";
        }
        if (secret.getStatus() == SecretStatus.EXPIRED || isExpired(secret, now)) {
            return "EXPIRED";
        }
        if (isViewLimitReached(secret)) {
            return "VIEW_LIMIT_REACHED";
        }
        if (secret.getPasswordHash() != null && !secret.getPasswordHash().isBlank()) {
            return "PASSWORD_REQUIRED";
        }
        return "READY";
    }

    /**
     * Full validation for POST /api/secrets/{id}/access. Order: status ->
     * expiration -> password -> view limit. Throws the first failing check;
     * callers should only consume a view if this returns normally.
     */
    public void validateAccess(Secret secret, String suppliedPassword, Instant now, PasswordEncoder passwordEncoder) {
        if (secret.getStatus() == SecretStatus.DELETED) {
            throw new SecretNotFoundException(secret.getId());
        }
        if (secret.getStatus() == SecretStatus.CONSUMED) {
            throw new SecretConsumedException(secret.getId());
        }
        if (secret.getStatus() == SecretStatus.EXPIRED || isExpired(secret, now)) {
            throw new SecretExpiredException(secret.getId());
        }
        if (secret.getPasswordHash() != null && !secret.getPasswordHash().isBlank()) {
            if (suppliedPassword == null || suppliedPassword.isBlank()
                    || !passwordEncoder.matches(suppliedPassword, secret.getPasswordHash())) {
                throw new InvalidPasswordException(secret.getId());
            }
        }
        if (isViewLimitReached(secret)) {
            throw new ViewLimitReachedException(secret.getId());
        }
    }

    private boolean isExpired(Secret secret, Instant now) {
        return secret.getExpiresAt() != null && now.isAfter(secret.getExpiresAt());
    }

    private boolean isViewLimitReached(Secret secret) {
        return secret.getMaxViews() != null && secret.getCurrentViews() >= secret.getMaxViews();
    }
}
