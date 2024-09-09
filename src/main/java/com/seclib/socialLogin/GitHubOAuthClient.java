package com.seclib.socialLogin;

import com.seclib.config.OAuth.GitHubOAuthProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URISyntaxException;

@Slf4j
@Service
public class GitHubOAuthClient extends BaseOAuthClient {

    private final GitHubOAuthProperties gitHubConfig;

    public GitHubOAuthClient(GitHubOAuthProperties config) throws URISyntaxException, IOException {
        super(config);
        this.gitHubConfig = config;
    }

    public String buildAuthorizationUrl() {
        return super.buildAuthorizationUrl(gitHubConfig.getAuthorizationEndpoint());
    }

    public TokenResponse exchangeCodeForToken(String code) throws IOException {
        return super.exchangeCodeForToken(code, gitHubConfig.getTokenEndpoint());
    }

    public GitHubUserProfile fetchUserProfile(String accessToken) throws IOException {
        return super.fetchUserProfile(accessToken, gitHubConfig.getUserInfoEndpoint(), GitHubUserProfile.class);
    }

}