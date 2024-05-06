// BasePasswordResetToken.java
package com.seclib.passwordResetToken.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import com.seclib.user.model.BaseUser;

import java.sql.Date;

@MappedSuperclass
public abstract class BasePasswordResetToken<T extends BaseUser> {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Getter
    @Setter
    private String token;

    @OneToOne(fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "user_id")
    @Setter
    @Getter
    private T user;

    @Getter
    @Setter
    private Date expiryDate;

    @Getter
    private static final int EXPIRATION = 5;

}