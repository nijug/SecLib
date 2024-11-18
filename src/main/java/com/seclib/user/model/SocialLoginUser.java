package com.seclib.user.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@Entity
public class SocialLoginUser extends BaseUser {

    @Column(name = "provider")
    private String provider;
    @Column(name = "provider_id")
    private String providerId;
    @Column(name = "email")
    private String email;
    @Column(name = "role")
    private String role;

    public SocialLoginUser(String username, String provider, String providerId, String email) {
        super(username, null);
        this.provider = provider;
        this.providerId = providerId;
        this.email = email;
    }
}