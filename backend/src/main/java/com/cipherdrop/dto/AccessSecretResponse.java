package com.cipherdrop.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class AccessSecretResponse {

    private String access;
    private String encryptedContent;
    private String iv;
}