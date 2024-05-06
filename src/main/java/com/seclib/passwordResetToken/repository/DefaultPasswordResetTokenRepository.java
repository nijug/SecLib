package com.seclib.passwordResetToken.repository;

import com.seclib.passwordResetToken.model.DefaultPasswordResetToken;
import com.seclib.user.model.DefaultUser;
import org.springframework.stereotype.Repository;

@Repository
public interface DefaultPasswordResetTokenRepository extends BasePasswordResetTokenRepository<DefaultPasswordResetToken, DefaultUser, Long> {
}