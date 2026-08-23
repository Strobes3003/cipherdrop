package com.cipherdrop.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Two shapes, same class, null fields omitted from JSON:
 *   Success: { "access": "ACCESS_GRANTED", "encryptedContent": "...", "iv": "..." }
 *   Denial:  { "access": "DENIED", "reason": "EXPIRED" }
 */
@Getter
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AccessSecretResponse {

    private String access;
    private String encryptedContent;
    private String iv;
    private String reason;

    public AccessSecretResponse(String access, String encryptedContent, String iv) {
        this(access, encryptedContent, iv, null);
    }

    public static AccessSecretResponse denied(String reason) {
        return new AccessSecretResponse("DENIED", null, null, reason);
    }
}