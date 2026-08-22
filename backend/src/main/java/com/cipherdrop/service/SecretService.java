package com.cipherdrop.service;

import com.cipherdrop.dto.AccessSecretRequest;
import com.cipherdrop.dto.AccessSecretResponse;
import com.cipherdrop.dto.CreateSecretRequest;
import com.cipherdrop.dto.CreateSecretResponse;
import com.cipherdrop.dto.SecretStatusResponse;
import com.cipherdrop.entity.Secret;
import com.cipherdrop.enums.SecretStatus;
import com.cipherdrop.exception.InvalidManagementTokenException;
import com.cipherdrop.exception.SecretNotFoundException;
import com.cipherdrop.policy.SecretPolicyEngine;
import com.cipherdrop.repository.SecretRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class SecretService {

    private final SecretRepository secretRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecretPolicyEngine policyEngine;

    public SecretService(
            SecretRepository secretRepository,
            PasswordEncoder passwordEncoder,
            SecretPolicyEngine policyEngine
    ) {
        this.secretRepository = secretRepository;
        this.passwordEncoder = passwordEncoder;
        this.policyEngine = policyEngine;
    }

    public CreateSecretResponse createSecret(CreateSecretRequest request) {

        String secretId = UUID.randomUUID().toString();
        String managementToken = UUID.randomUUID().toString();

        Secret secret = Secret.builder()
                .id(secretId)
                .encryptedContent(request.getEncryptedContent())
                .iv(request.getIv())
                .passwordHash(
                        request.getPassword() != null && !request.getPassword().isBlank()
                                ? passwordEncoder.encode(request.getPassword())
                                : null
                )
                .expiresAt(request.getExpiresAt())
                .burnAfterReading(request.isBurnAfterReading())
                .maxViews(request.getMaxViews())
                .currentViews(0)
                .status(SecretStatus.ACTIVE)
                .createdAt(Instant.now())
                .managementTokenHash(passwordEncoder.encode(managementToken))
                .build();

        secretRepository.save(secret);

        return new CreateSecretResponse(
                secretId,
                managementToken
        );
    }

    /**
     * GET /api/secrets/{id}. Read-only - never mutates, never returns ciphertext.
     * Policy checks delegated to SecretPolicyEngine.
     */
    public SecretStatusResponse getSecretStatus(String secretId) {
        Secret secret = secretRepository.findById(secretId)
                .orElseThrow(() -> new SecretNotFoundException(secretId));

        String access = policyEngine.resolveAccessState(secret, Instant.now());
        return new SecretStatusResponse(access);
    }

    /**
     * POST /api/secrets/{id}/access. Concurrency-critical: findByIdForUpdate
     * takes a pessimistic row lock, so a second concurrent request for the
     * same secret blocks until this transaction commits and only then
     * re-reads the up-to-date currentViews/status - two requests can't both
     * be granted the last view.
     */
    @Transactional
    public AccessSecretResponse accessSecret(String secretId, AccessSecretRequest request) {

        Secret secret = secretRepository.findByIdForUpdate(secretId)
                .orElseThrow(() -> new SecretNotFoundException(secretId));

        Instant now = Instant.now();

        // Throws a typed exception (handled by GlobalExceptionHandler) on the
        // first failing check: status -> expiration -> password -> view limit.
        policyEngine.validateAccess(secret, request.getPassword(), now, passwordEncoder);

        // Access granted: consume the view atomically within this locked transaction.
        secret.setCurrentViews(secret.getCurrentViews() + 1);

        if (secret.isBurnAfterReading()) {
            secret.setStatus(SecretStatus.CONSUMED);
            secret.setConsumedAt(now);
        }

        secretRepository.save(secret);

        return new AccessSecretResponse(
                "ACCESS_GRANTED",
                secret.getEncryptedContent(),
                secret.getIv()
        );
    }

    /**
     * DELETE /api/secrets/{id}. Verifies the raw Bearer management token
     * against management_token_hash, then soft-deletes to DELETED status.
     */
    @Transactional
    public void deleteSecret(String secretId, String rawManagementToken) {
        Secret secret = secretRepository.findById(secretId)
                .orElseThrow(() -> new SecretNotFoundException(secretId));

        if (rawManagementToken == null || rawManagementToken.isBlank()
                || !passwordEncoder.matches(rawManagementToken, secret.getManagementTokenHash())) {
            throw new InvalidManagementTokenException(secretId);
        }

        secret.setStatus(SecretStatus.DELETED);
        secretRepository.save(secret);
    }
}
