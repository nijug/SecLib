package com.seclib.user.repository;

import com.seclib.user.model.SocialLoginUser;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SocialLoginUserRepository extends BaseUserRepository<SocialLoginUser, Long> {
    Optional<SocialLoginUser> findByProviderAndProviderId(String provider, String providerId);
}