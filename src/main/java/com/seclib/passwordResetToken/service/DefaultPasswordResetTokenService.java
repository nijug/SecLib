package com.seclib.passwordResetToken.service;

import com.seclib.passwordResetToken.model.DefaultPasswordResetToken;
import com.seclib.passwordResetToken.repository.DefaultPasswordResetTokenRepository;
import com.seclib.user.model.DefaultUser;
import org.springframework.stereotype.Service;

@Service
public class DefaultPasswordResetTokenService extends BasePasswordResetTokenService<DefaultPasswordResetToken, DefaultUser, DefaultPasswordResetTokenRepository> {

    public DefaultPasswordResetTokenService(DefaultPasswordResetTokenRepository passwordResetTokenRepository) {
        super(passwordResetTokenRepository);
    }

    @Override
    protected DefaultPasswordResetToken createInstance() {
        return new DefaultPasswordResetToken();
    }
}