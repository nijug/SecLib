package com.seclib.user.dto;

import lombok.Getter;
import lombok.Setter;


import lombok.Getter;
import lombok.Setter;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Setter
@Getter
public abstract class BaseUserDTO {
    @NotNull
    private Long id;

    @NotNull(message = "Username cannot be null")
    @Size(min = 3, message = "Username must be at least 3 characters")
    private String username;

    @NotNull(message = "Password cannot be null")
    private String password;
}
