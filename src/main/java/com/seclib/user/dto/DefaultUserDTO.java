package com.seclib.user.dto;


import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class DefaultUserDTO extends BaseUserDTO {

    private String totpSecret;
    private String role;
    private String csrfToken;
}
