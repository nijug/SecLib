package com.seclib.twoFA.service;

import jakarta.servlet.http.HttpSession;
import org.jboss.aerogear.security.otp.Totp;
import org.jboss.aerogear.security.otp.api.Base32;

public abstract class BaseTotpService {

    public String generateSecretKey() {
        return Base32.random();
    }

    public String generateTotp(String secretKey) {
        Totp totp = new Totp(secretKey);
        return totp.now();
    }

    public boolean validateTotp(String secretKey, String totp, HttpSession session) {
        String lastUsedTotp = (String) session.getAttribute("lastUsedTotp");
        Long lastUsedTotpTime = (Long) session.getAttribute("lastUsedTotpTime");

        if (totp.equals(lastUsedTotp) && System.currentTimeMillis() - lastUsedTotpTime < 30000) {
            return false;
        }

        Totp totpGenerator = new Totp(secretKey);
        boolean valid = totpGenerator.verify(totp);

        if (valid) {
            session.setAttribute("lastUsedTotp", totp);
            session.setAttribute("lastUsedTotpTime", System.currentTimeMillis());
        }

        return valid;
    }
}