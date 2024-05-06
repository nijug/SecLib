package com.seclib.passwordResetToken.repository;

import com.seclib.passwordResetToken.model.BasePasswordResetToken;
import com.seclib.user.model.BaseUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

import java.io.Serializable;

@NoRepositoryBean
public interface BasePasswordResetTokenRepository<T extends BasePasswordResetToken<U>, U extends BaseUser, ID extends Serializable> extends JpaRepository<T, ID> {

    T findByUser(U user);
    T findByToken(String token);

}
