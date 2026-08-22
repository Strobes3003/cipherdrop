package com.cipherdrop.service;

import com.cipherdrop.dto.CreateSecretRequest;
import com.cipherdrop.dto.CreateSecretResponse;
import com.cipherdrop.dto.AccessSecretRequest;
import com.cipherdrop.dto.AccessSecretResponse;
import com.cipherdrop.dto.SecretStatusResponse;
import com.cipherdrop.entity.Secret;
import com.cipherdrop.enums.SecretStatus;
import com.cipherdrop.repository.SecretRepository;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class SecretService {

    private final SecretRepository secretRepository;
    private final PasswordEncoder passwordEncoder;

    public SecretService(
            SecretRepository secretRepository,
            PasswordEncoder passwordEncoder
    ) {
        this.secretRepository = secretRepository;
        this.passwordEncoder = passwordEncoder;
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
    public SecretStatusResponse getSecretStatus(String secretId) {

        Secret secret = secretRepository.findById(secretId)
                .orElseThrow(() -> new RuntimeException("Secret not found"));

        // Check status
        if (secret.getStatus() == SecretStatus.CONSUMED) {
            return new SecretStatusResponse("CONSUMED");
        }

        if (secret.getStatus() == SecretStatus.DELETED) {
            return new SecretStatusResponse("DELETED");
        }

        if (secret.getStatus() == SecretStatus.EXPIRED) {
            return new SecretStatusResponse("EXPIRED");
        }

        // Check expiration
        if (secret.getExpiresAt() != null &&
                Instant.now().isAfter(secret.getExpiresAt())) {

            secret.setStatus(SecretStatus.EXPIRED);
            secretRepository.save(secret);

            return new SecretStatusResponse("EXPIRED");
        }

        // Check view limit
        if (secret.getMaxViews() != null &&
                secret.getCurrentViews() >= secret.getMaxViews()) {

            return new SecretStatusResponse("VIEW_LIMIT_REACHED");
        }

        // Check whether password is required
        if (secret.getPasswordHash() != null) {
            return new SecretStatusResponse("PASSWORD_REQUIRED");
        }

        return new SecretStatusResponse("READY");
    }
    @Transactional
    public AccessSecretResponse accessSecret(String secretId, AccessSecretRequest request) {

        Secret secret = secretRepository.findByIdForUpdate(secretId)
                .orElseThrow(() -> new RuntimeException("Secret not found"));

        // Check status
        if (secret.getStatus() != SecretStatus.ACTIVE) {
            throw new RuntimeException("Secret is no longer active");
        }

        // Check expiration
        if (secret.getExpiresAt() != null &&
                Instant.now().isAfter(secret.getExpiresAt())) {

            secret.setStatus(SecretStatus.EXPIRED);
            secretRepository.save(secret);

            throw new RuntimeException("Secret has expired");
        }

        // Check password if one was configured
        if (secret.getPasswordHash() != null) {

            if (request.getPassword() == null ||
                    !passwordEncoder.matches(
                            request.getPassword(),
                            secret.getPasswordHash()
                    )) {

                throw new RuntimeException("Invalid password");
            }
        }

        // Check maximum views
        if (secret.getMaxViews() != null &&
                secret.getCurrentViews() >= secret.getMaxViews()) {

            secret.setStatus(SecretStatus.CONSUMED);
            secretRepository.save(secret);

            throw new RuntimeException("Maximum views reached");
        }

        // Count this access
        secret.setCurrentViews(secret.getCurrentViews() + 1);

        // Burn after reading
        if (secret.isBurnAfterReading()) {
            secret.setStatus(SecretStatus.CONSUMED);
            secret.setConsumedAt(Instant.now());
        }

        secretRepository.save(secret);

        return new AccessSecretResponse(
                "ACCESS_GRANTED",
                secret.getEncryptedContent(),
                secret.getIv()
        );
    }
}
