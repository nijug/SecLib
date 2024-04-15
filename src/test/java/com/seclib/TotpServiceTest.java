package com.seclib;

import com.seclib.Totp.service.DefaultTotpService;
import org.jboss.aerogear.security.otp.Totp;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import jakarta.servlet.http.HttpSession;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class TotpServiceTest {

    @Mock
    private HttpSession session;

    @InjectMocks
    private DefaultTotpService totpService;

    @Test
    public void testGenerateSecretKey() {
        String secretKey = totpService.generateSecretKey();
        assertNotNull(secretKey);
        assertEquals(16, secretKey.length());
    }

    @Test
    public void testValidateTotp() {
        String secretKey = totpService.generateSecretKey();
        Totp totpGenerator = new Totp(secretKey);
        String totp = totpGenerator.now();

        Mockito.when(session.getAttribute("lastUsedTotp")).thenReturn(null);
        Mockito.when(session.getAttribute("lastUsedTotpTime")).thenReturn(null);

        boolean isValid = totpService.validateTotp(secretKey, totp, session);
        assertTrue(isValid);
    }

    @Test
    public void testGenerateQRCodeImage() throws Exception {
        String secretKey = totpService.generateSecretKey();
        byte[] qrCodeImage = totpService.generateQRCodeImage(secretKey, 200, 200);
        assertNotNull(qrCodeImage);
    }

    @Test
    public void testValidateInvalidTotp() {
        String secretKey = totpService.generateSecretKey();
        String invalidTotp = "123456";

        Mockito.when(session.getAttribute("lastUsedTotp")).thenReturn(null);
        Mockito.when(session.getAttribute("lastUsedTotpTime")).thenReturn(null);

        boolean isValid = totpService.validateTotp(secretKey, invalidTotp, session);
        assertFalse(isValid);
    }

    @Test
    public void testValidateReusedTotp() {
        String secretKey = totpService.generateSecretKey();
        Totp totpGenerator = new Totp(secretKey);
        String totp = totpGenerator.now();

        Mockito.when(session.getAttribute("lastUsedTotp")).thenReturn(totp);
        Mockito.when(session.getAttribute("lastUsedTotpTime")).thenReturn(System.currentTimeMillis());

        boolean isValid = totpService.validateTotp(secretKey, totp, session);
        assertFalse(isValid);
    }

    @Test
    public void testGenerateQRCodeImageWithDifferentSizes() throws Exception {
        String secretKey = totpService.generateSecretKey();
        byte[] qrCodeImageSmall = totpService.generateQRCodeImage(secretKey, 100, 100);
        byte[] qrCodeImageLarge = totpService.generateQRCodeImage(secretKey, 500, 500);

        assertNotNull(qrCodeImageSmall);
        assertNotNull(qrCodeImageLarge);
        assertTrue(qrCodeImageLarge.length > qrCodeImageSmall.length);
    }
}