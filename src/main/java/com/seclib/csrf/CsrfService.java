package com.seclib.csrf;

import jakarta.servlet.http.HttpSession;

import java.security.SecureRandom;
import java.util.Base64;


public class CsrfService {

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


}
