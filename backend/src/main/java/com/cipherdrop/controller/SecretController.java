package com.cipherdrop.controller;

import com.cipherdrop.dto.CreateSecretRequest;
import com.cipherdrop.dto.CreateSecretResponse;
import com.cipherdrop.service.SecretService;
import jakarta.validation.Valid;
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
}