package com.cipherdrop.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

/** Generic error body: { "reason": "NOT_FOUND" }, { "reason": "INVALID_MANAGEMENT_TOKEN" }, etc. */
@Getter
@AllArgsConstructor
public class ErrorResponse {
    private String reason;
}
