package com.seclib.passwordResetToken.model;

import com.seclib.user.model.DefaultUser;
import jakarta.persistence.Entity;

@Entity
public class DefaultPasswordResetToken extends BasePasswordResetToken<DefaultUser> {
}