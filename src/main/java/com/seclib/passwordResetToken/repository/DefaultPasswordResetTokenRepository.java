package com.seclib.passwordResetToken.repository;

import com.seclib.passwordResetToken.model.DefaultPasswordResetToken;
import com.seclib.user.model.DefaultUser;


public interface DefaultPasswordResetTokenRepository extends BasePasswordResetTokenRepository<DefaultPasswordResetToken, DefaultUser, Long> {
}