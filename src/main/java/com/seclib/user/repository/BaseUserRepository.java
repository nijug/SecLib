package com.seclib.user.repository;

import com.seclib.user.model.BaseUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

import java.io.Serializable;
import java.util.Optional;

@NoRepositoryBean
public interface BaseUserRepository<T extends BaseUser, ID extends Serializable> extends JpaRepository<T, ID> {
    Optional<T> findByUsername(String username);
}