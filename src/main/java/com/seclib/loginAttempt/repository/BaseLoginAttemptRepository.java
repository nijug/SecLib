package com.seclib.loginAttempt.repository;

import com.seclib.loginAttempt.model.BaseLoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

import java.io.Serializable;
import java.util.Optional;

@NoRepositoryBean
public interface BaseLoginAttemptRepository<T extends BaseLoginAttempt, ID extends Serializable> extends JpaRepository<T, ID> {
    Optional<T> findByIpAddress(String ipAddress);
}