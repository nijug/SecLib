package com.seclib.socialLogin;
import lombok.Data;

@Data
public class TokenResponse {
    private String accessToken;
    private String idToken;
    private String refreshToken;
    private Long expiresIn;
    private String scope;

}
