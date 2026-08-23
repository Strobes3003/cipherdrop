package com.cipherdrop.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class CreateSecretResponse {

    private String id;

    private String managementToken;
}
