package com.cipherdrop.repository;

import com.cipherdrop.entity.Secret;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface SecretRepository extends JpaRepository<Secret, String> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT s FROM Secret s WHERE s.id = :id")
    Optional<Secret> findByIdForUpdate(String id);
}