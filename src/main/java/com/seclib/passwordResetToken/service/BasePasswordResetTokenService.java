package com.seclib.passwordResetToken.service;

import com.seclib.passwordResetToken.model.BasePasswordResetToken;
import com.seclib.passwordResetToken.repository.BasePasswordResetTokenRepository;
import com.seclib.user.model.BaseUser;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public abstract class BasePasswordResetTokenService<U extends BaseUser, T extends BasePasswordResetToken<U>, R extends BasePasswordResetTokenRepository<T, U, Long>> {

    protected final R passwordResetTokenRepository;

    public BasePasswordResetTokenService(R passwordResetTokenRepository) {
        this.passwordResetTokenRepository = passwordResetTokenRepository;
    }

    public T createPasswordResetToken(U user) {
        Optional<T> existingToken = passwordResetTokenRepository.findByUser(user);
        existingToken.ifPresent(passwordResetTokenRepository::delete);
        T token = createInstance();
        token.setUser(user);
        token.setToken(UUID.randomUUID().toString());
        token.setExpiryDate(calculateExpiryDate(BasePasswordResetToken.getEXPIRATION()));
        return passwordResetTokenRepository.save(token);
    }

    public Optional<T> getPasswordResetToken(String token) {
        return passwordResetTokenRepository.findByToken(token);
    }

    public void deletePasswordResetToken(T token) {
        passwordResetTokenRepository.delete(token);
    }

    protected abstract T createInstance();

    private Instant calculateExpiryDate(int expiryTimeInMinutes) {
        return Instant.now().plusSeconds(expiryTimeInMinutes * 60L);
    }
}