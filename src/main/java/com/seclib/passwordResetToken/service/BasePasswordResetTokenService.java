package com.seclib.passwordResetToken.service;

import com.seclib.passwordResetToken.model.BasePasswordResetToken;
import com.seclib.passwordResetToken.repository.*;
import com.seclib.user.model.BaseUser;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.UUID;

@Service
public abstract class BasePasswordResetTokenService<T extends BasePasswordResetToken<U>, U extends BaseUser, R extends BasePasswordResetTokenRepository<T, U, Long>> {

    protected R passwordResetTokenRepository;

    public BasePasswordResetTokenService(R passwordResetTokenRepository) {
        this.passwordResetTokenRepository = passwordResetTokenRepository;
    }

    public T createPasswordResetToken(U user) {
        T existingToken = passwordResetTokenRepository.findByUser(user);
        if (existingToken != null) {
            passwordResetTokenRepository.delete(existingToken);
        }
        T token = createInstance();
        token.setUser(user);
        token.setToken(UUID.randomUUID().toString());
        token.setExpiryDate(calculateExpiryDate(BasePasswordResetToken.getEXPIRATION()));
        return passwordResetTokenRepository.save(token);
    }

    public T getPasswordResetToken(String token) {
        return passwordResetTokenRepository.findByToken(token);
    }

    public void deletePasswordResetToken(T token) {
        passwordResetTokenRepository.delete(token);
    }

    protected abstract T createInstance();

    private java.sql.Date calculateExpiryDate(int expiryTimeInMinutes) {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MINUTE, expiryTimeInMinutes);
        return new java.sql.Date(cal.getTime().getTime());
    }
}