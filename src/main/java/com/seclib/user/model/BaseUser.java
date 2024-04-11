package com.seclib.user.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import java.util.Objects;

@MappedSuperclass
public abstract class BaseUser {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @NotNull(message = "Password cannot be null")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Getter
    @Setter
    private String password;

    @Getter
    @Setter // for testing purposes
    @Column(name = "failed_attempts")
    private int failedAttempts = 0;

    @Getter
    @Setter
    @Column(name = "lock_time")
    private long lockTime = 0;

    @Getter
    @Setter
    private String totpSecret;


    protected BaseUser(Long id, String password) {
        this.id = id;
        this.password = password;
    }



    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BaseUser baseUser = (BaseUser) o;
        return Objects.equals(id, baseUser.id) &&
                Objects.equals(password, baseUser.password);
    }

    public Long getId() {
        System.out.println("id: " + id);
        return id;
    }
    @Override
    public int hashCode() {
        return Objects.hash(id, password);
    }

    protected BaseUser() {
    }

    public void resetFailedAttempts() {
        this.failedAttempts = 0;
    }

    public void incrementFailedAttempts() {
        this.failedAttempts++;
    }
}