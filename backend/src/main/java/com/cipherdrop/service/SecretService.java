package com.cipherdrop.service;

import com.cipherdrop.dto.CreateSecretRequest;
import com.cipherdrop.dto.CreateSecretResponse;
import com.cipherdrop.entity.Secret;
import com.cipherdrop.enums.SecretStatus;
import com.cipherdrop.repository.SecretRepository;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;

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
}
