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

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

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

    public String buildAuthorizationUrl(String state) {
        URIBuilder uriBuilder = null;
        try {
            uriBuilder = new URIBuilder(config.getAuthorizationEndpoint());
            uriBuilder.addParameter("client_id", config.getClientId());
            uriBuilder.addParameter("redirect_uri", config.getRedirectUri());
            uriBuilder.addParameter("scope", String.join(" ", config.getScopes()));
            uriBuilder.addParameter("state", state);
            uriBuilder.addParameter("response_type", "code");
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        log.info("Authorization URL built: {}", uriBuilder);
        return uriBuilder.toString();
    }

    public TokenResponse exchangeCodeForToken(String code, String tokenEndpoint) throws IOException {
        log.info("Exchanging code for token. Code: {}, Token Endpoint: {}", code, tokenEndpoint);

        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("client_id", config.getClientId()));
        params.add(new BasicNameValuePair("client_secret", config.getClientSecret()));
        params.add(new BasicNameValuePair("code", code));
        params.add(new BasicNameValuePair("redirect_uri", config.getRedirectUri()));
        params.add(new BasicNameValuePair("grant_type", "authorization_code"));

        for (NameValuePair param : params) {
            log.info("Parameter for token: {} = {}", param.getName(), param.getValue());
        }

        return executePostRequest(tokenEndpoint, params);
    }


    public UserProfile fetchUserProfile(String accessToken, String userInfoEndpoint) throws IOException {
        String jsonResponse = executeGetRequest(userInfoEndpoint, accessToken);
        return parseResponse(jsonResponse, UserProfile.class);
    }


    protected void handleErrorResponse(HttpResponse response) throws IOException {
        String jsonResponse = EntityUtils.toString(response.getEntity());
        log.error("Error response: {}", jsonResponse);
        throw new OAuthException(401, "Error handling 0Auth procedure");
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

    protected <T> T parseResponse(String jsonResponse, Class<T> responseType) throws IOException {
        return objectMapper.readValue(jsonResponse, responseType);
    }

    public TokenResponse refreshToken(String refreshToken, String tokenEndpoint) throws IOException {
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("client_id", config.getClientId()));
        params.add(new BasicNameValuePair("client_secret", config.getClientSecret()));
        params.add(new BasicNameValuePair("refresh_token", refreshToken));
        params.add(new BasicNameValuePair("grant_type", "refresh_token"));

        for (NameValuePair param : params) {
            log.info("Parameter for token refresh: {} = {}", param.getName(), param.getValue());
        }

        return executePostRequest(tokenEndpoint, params);
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
