package com.cipherdrop.entity;

import com.cipherdrop.enums.SecretStatus;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "secrets")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Secret {

    @Id
    private String id;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedContent;

    @Column(nullable = false)
    private String iv;

    private String passwordHash;

    @Column(nullable = false)
    private String managementTokenHash;

    private Instant expiresAt;

    @Column(nullable = false)
    private boolean burnAfterReading;

    private Integer maxViews;

    @Column(nullable = false)
    private int currentViews;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SecretStatus status;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    private Instant consumedAt;
}