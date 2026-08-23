package com.cipherdrop.controller;

import com.cipherdrop.dto.CreateSecretRequest;
import com.cipherdrop.dto.CreateSecretResponse;
import com.cipherdrop.service.SecretService;
import com.cipherdrop.dto.AccessSecretRequest;
import com.cipherdrop.dto.AccessSecretResponse;
import com.cipherdrop.dto.SecretStatusResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/secrets")
public class SecretController {

    private final SecretService secretService;

    public SecretController(SecretService secretService) {
        this.secretService = secretService;
    }

    @PostMapping
    public ResponseEntity<CreateSecretResponse> createSecret(
            @Valid @RequestBody CreateSecretRequest request
    ) {
        CreateSecretResponse response = secretService.createSecret(request);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/{id}")
    public ResponseEntity<SecretStatusResponse> getSecretStatus(
            @PathVariable String id
    ) {
        SecretStatusResponse response =
                secretService.getSecretStatus(id);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/{id}/access")
    public ResponseEntity<AccessSecretResponse> accessSecret(
            @PathVariable String id,
            @RequestBody(required = false) AccessSecretRequest request
    ) {
        if (request == null) {
            request = new AccessSecretRequest();
        }

        AccessSecretResponse response =
                secretService.accessSecret(id, request);

        return ResponseEntity.ok(response);
    }

    /**
     * Management token supplied as: Authorization: Bearer MANAGEMENT_TOKEN
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteSecret(
            @PathVariable String id,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader
    ) {
        String token = extractBearerToken(authorizationHeader);
        secretService.deleteSecret(id, token);
        return ResponseEntity.noContent().build();
    }

    private String extractBearerToken(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return null;
        }
        return authorizationHeader.substring("Bearer ".length()).trim();
    }
}