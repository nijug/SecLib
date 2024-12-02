package com.seclib.socialLogin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.seclib.config.OAuth.BaseOAuthProperties;
import com.seclib.exception.OAuthException;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Slf4j
public abstract class BaseOAuthClient {

    protected final BaseOAuthProperties config;
    protected final CloseableHttpClient httpClient;
    protected final ObjectMapper objectMapper;

    protected BaseOAuthClient(BaseOAuthProperties config) {
        this.config = config;
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(10 * 1000)
                .setSocketTimeout(10 * 1000)
                .build();
        this.httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build();
        this.objectMapper = new ObjectMapper();
    }

    protected String buildAuthorizationUrl(String authorizationEndpoint, HttpServletResponse response, String stateData) {
        URIBuilder uriBuilder;
        try {
            uriBuilder = new URIBuilder(authorizationEndpoint);
            uriBuilder.addParameter("client_id", config.getClientId());
            uriBuilder.addParameter("redirect_uri", config.getRedirectUri());
            uriBuilder.addParameter("scope", String.join(" ", config.getScopes()));
            String state = generateState(response, stateData);
            if (state != null && !state.isEmpty()) {
                uriBuilder.addParameter("state", state);
            }
            uriBuilder.addParameter("response_type", config.getResponseType());
        } catch (URISyntaxException e) {
            log.error("Error building authorization URL", e);
            throw new RuntimeException(e);
        }
        log.info("Authorization URL built: {}", uriBuilder);
        return uriBuilder.toString();
    }

    private String generateState(HttpServletResponse response, String stateData) {
        if (!config.isAllowStateToPassData() && config.getState() != null && !config.getState().isEmpty()) {
            return config.getState();
        } else {
            String nonce = UUID.randomUUID().toString();
            storeNonceInCookie(nonce, stateData, response);
            return Base64.getUrlEncoder().encodeToString(nonce.getBytes(StandardCharsets.UTF_8));
        }
    }

    private void storeNonceInCookie(String nonce, String frontendRedirectUri, HttpServletResponse response) {
        Cookie cookie = new Cookie(nonce, frontendRedirectUri);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(300);
        response.addCookie(cookie);
    }

    public String retrieveDataFromState(String state, HttpServletRequest request) {
        if (!config.isAllowStateToPassData() && config.getState() != null && !config.getState().isEmpty()) {
            return null;
        } else {
            String nonce = new String(Base64.getUrlDecoder().decode(state), StandardCharsets.UTF_8);
            return retrieveDataFromCookie(nonce, request);
        }
    }

    private String retrieveDataFromCookie(String nonce, HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(nonce)) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    public TokenResponse exchangeCodeForToken(String code, String tokenEndpoint) throws IOException {
        log.info("Exchanging code for token. Code: {}, Token Endpoint: {}", code, tokenEndpoint);

        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("client_id", config.getClientId()));
        params.add(new BasicNameValuePair("client_secret", config.getClientSecret()));
        params.add(new BasicNameValuePair("code", code));
        params.add(new BasicNameValuePair("redirect_uri", config.getRedirectUri()));
        params.add(new BasicNameValuePair("grant_type", config.getGrantType()));

        for (NameValuePair param : params) {
            log.info("Parameter for token: {} = {}", param.getName(), param.getValue());
        }

        return executePostRequest(tokenEndpoint, params);
    }

    protected <T extends BaseUserProfile> T fetchUserProfile(String accessToken, String userInfoEndpoint, Class<T> userProfileClass) throws IOException {
        String jsonResponse = executeGetRequest(userInfoEndpoint, accessToken);
        return parseResponse(jsonResponse, userProfileClass);
    }

    protected void handleErrorResponse(HttpResponse response) throws IOException {
        String jsonResponse = EntityUtils.toString(response.getEntity());
        log.error("Error response: {}", jsonResponse);
        throw new OAuthException(401, "Error handling OAuth procedure");
    }

    protected String executeGetRequest(String url, String accessToken) throws IOException {
        HttpGet httpGet = new HttpGet(url);
        httpGet.setHeader(new BasicHeader("Authorization", "Bearer " + accessToken));
        try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode != 200) {
                handleErrorResponse(response);
            }
            return EntityUtils.toString(response.getEntity());
        }
    }

    private <T> T parseResponse(String jsonResponse, Class<T> responseType) throws IOException {
        return objectMapper.readValue(jsonResponse, responseType);
    }

    protected TokenResponse executePostRequest(String tokenEndpoint, List<NameValuePair> params) throws IOException {
        HttpPost httpPost = new HttpPost(tokenEndpoint);
        httpPost.setHeader("Accept", "application/json");
        httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded");
        httpPost.setEntity(new UrlEncodedFormEntity(params));

        try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
            int statusCode = response.getStatusLine().getStatusCode();
            log.info("POST request response status: {}", statusCode);
            if (statusCode != 200) {
                handleErrorResponse(response);
            }
            String jsonResponse = EntityUtils.toString(response.getEntity());
            TokenResponse tokenResponse = objectMapper.readValue(jsonResponse, TokenResponse.class);
            log.info("Parsed token response: {}", tokenResponse);
            return tokenResponse;
        }
    }
}


