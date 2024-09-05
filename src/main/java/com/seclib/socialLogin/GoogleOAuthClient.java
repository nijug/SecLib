package com.seclib.socialLogin;

import com.seclib.config.OAuth.GoogleOAuthProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Slf4j
@Service
public class GoogleOAuthClient extends BaseOAuthClient {

    private final GoogleOAuthProperties googleConfig;

    public GoogleOAuthClient(GoogleOAuthProperties config) {
        super(config);
        this.googleConfig = config;
    }

    public TokenResponse exchangeCodeForToken(String code) throws IOException {
        return super.exchangeCodeForToken(code, googleConfig.getTokenEndpoint());
    }

    public UserProfile fetchUserProfile(String accessToken) throws IOException {
        return super.fetchUserProfile(accessToken, googleConfig.getUserInfoEndpoint());
    }

    public TokenResponse refreshToken(String refreshToken) throws IOException {
        return super.refreshToken(refreshToken, googleConfig.getTokenEndpoint());
    }
}


