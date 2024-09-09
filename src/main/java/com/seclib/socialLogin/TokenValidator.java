package com.seclib.socialLogin;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;


@Slf4j
public class TokenValidator {
    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public TokenValidator(String jwksUrl) throws URISyntaxException, IOException {
        URI jwkSetURI = new URI(jwksUrl);
        JWKSource<SecurityContext> jwkSource = (jwkSelector, context) -> {
            JWKSet jwkSet;
            try {
                jwkSet = JWKSet.load(jwkSetURI.toURL());
            } catch (IOException | ParseException e) {
                log.error("Failed to load JWKSet from URI", e);
                throw new RuntimeException(e);
            }
            return jwkSelector.select(jwkSet);
        };

        JWSKeySelector<SecurityContext> keySelector = new JWSAlgorithmFamilyJWSKeySelector<>(JWSAlgorithm.Family.RSA, jwkSource);

        jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(keySelector);
    }

    public boolean validate(String idToken) throws ParseException, JOSEException, BadJOSEException {
        log.info("Validating ID token: {}", idToken);
        SignedJWT signedJWT = SignedJWT.parse(idToken);
        try {
            jwtProcessor.process(signedJWT, null);
            log.info("Token validation successful");
            return true;
        } catch (Exception e) {
            log.error("Token validation failed", e);
            return false;
        }
    }
}