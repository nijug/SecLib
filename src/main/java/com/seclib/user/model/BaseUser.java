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

    @NotNull(message = "Username cannot be null")
    @Size(min = 3, message = "Username must be at least 3 characters")
    @Column(unique = true)
    @Getter
    @Setter
    private String username;

    protected BaseUser(String username, String password) {
        this.password = password;
        this.username = username;
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


}