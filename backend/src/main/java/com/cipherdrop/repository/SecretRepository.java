package com.cipherdrop.repository;

import com.cipherdrop.entity.Secret;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecretRepository extends JpaRepository<Secret, String> {
}
