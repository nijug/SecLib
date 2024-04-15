// BasePasswordResetToken.java
package com.seclib.passwordReset.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import com.seclib.user.model.BaseUser;

import java.sql.Date;

@MappedSuperclass
public abstract class BasePasswordResetToken<T extends BaseUser> {

    @Getter
    private static final int EXPIRATION = 5;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Getter
    @Setter
    private String token;

    @OneToOne(fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "user_id")
    private T user;

    @Getter
    private Date expiryDate;


}