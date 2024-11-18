package com.seclib.user.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class SocialLoginUserDTO extends BaseUserDTO {
    private String role;
    private String sessionId;
    private String csrfToken;
    private String email;
}
