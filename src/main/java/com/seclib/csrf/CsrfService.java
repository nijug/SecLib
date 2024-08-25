package com.seclib.csrf;

import jakarta.servlet.http.HttpSession;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;


public class CsrfService {

    private final String formSecret;

    public CsrfService(String formSecret){
        this.formSecret = formSecret;
    }

    public String generateToken() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().encodeToString(tokenBytes);
    }

    public void storeToken(HttpSession session, String token) {
        session.setAttribute("CSRF_TOKEN", token);
    }

    public String getToken(HttpSession session) {
        return (String) session.getAttribute("CSRF_TOKEN");
    }

    public boolean validateToken(HttpSession session, String token) {
        String sessionToken = (String) session.getAttribute("CSRF_TOKEN");
        return token != null && token.equals(sessionToken);
    }

    public String generateNonce() {
        return UUID.randomUUID().toString();
    }

    public void storeNonce(HttpSession session, String nonce) {
        session.setAttribute("CSRF_NONCE", nonce);
    }

    public String getNonce(HttpSession session) {
        return (String) session.getAttribute("CSRF_NONCE");
    }

    public String generateFormHash(HttpSession session, String functionName) {
        String sessionId = session.getId();
        String data = sessionId + functionName + formSecret;
        return hash(data);
    }

    private String hash(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(data.getBytes());
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
