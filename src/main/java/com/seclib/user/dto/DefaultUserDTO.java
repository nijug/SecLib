package com.seclib.user.dto;


import jakarta.validation.constraints.Email;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class DefaultUserDTO extends BaseUserDTO {

    private String totpSecret;
    private String role;
    private String csrfToken;
    @Email(message = "Email should be valid")
    private String email;
    private String sessionId;

}
