package com.seclib.user.dto;

import lombok.Getter;
import lombok.Setter;


@Setter
@Getter
public abstract class BaseUserDTO {
    private Long id;
    private String username;
    private String password;
}