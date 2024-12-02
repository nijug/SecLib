package com.seclib.socialLogin;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.seclib.config.OAuth.GoogleOAuthProperties;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URISyntaxException;
import java.text.ParseException;

@Slf4j
@Service
public class GoogleOAuthClient extends BaseOAuthClient {

    private final GoogleOAuthProperties googleConfig;
    private final TokenValidator tokenValidator;

    public GoogleOAuthClient(GoogleOAuthProperties config) throws URISyntaxException, IOException {
        super(config);
        this.googleConfig = config;
        this.tokenValidator = new TokenValidator(googleConfig.getJwksUrl());
    }

    public String buildAuthorizationUrl() {
        return super.buildAuthorizationUrl(googleConfig.getAuthorizationEndpoint(),null, null);
    }

    public String buildAuthorizationUrl(HttpServletResponse response, String stateData) {
        return super.buildAuthorizationUrl(googleConfig.getAuthorizationEndpoint(), response, stateData);
    }

    public TokenResponse exchangeCodeForToken(String code) throws IOException, ParseException, JOSEException, BadJOSEException {
        TokenResponse tokenResponse = super.exchangeCodeForToken(code, googleConfig.getTokenEndpoint());

        if (tokenValidator.validate(tokenResponse.getIdToken())) {
            return tokenResponse;
        } else {
            throw new BadJOSEException("Invalid ID token");
        }
    }

    public GoogleUserProfile fetchUserProfile(String accessToken) throws IOException {
        return super.fetchUserProfile(accessToken, googleConfig.getUserInfoEndpoint(), GoogleUserProfile.class);
    }

}


