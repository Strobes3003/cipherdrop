package com.cipherdrop.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CreateSecretRequest {

    @NotBlank
    private String encryptedContent;

    @NotBlank
    private String iv;

    private Instant expiresAt;

    private boolean burnAfterReading;

    private Integer maxViews;

    private String password;
}
