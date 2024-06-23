package com.seclib.Totp.service;

import com.seclib.exception.QRCodeGenerationException;
import jakarta.servlet.http.HttpSession;
import org.jboss.aerogear.security.otp.Totp;
import org.jboss.aerogear.security.otp.api.Base32;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import com.google.zxing.client.j2se.MatrixToImageWriter;


public abstract class BaseTotpService {

    public String generateSecretKey() {
        return Base32.random();
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

    public byte[] generateQRCodeImage(String text, int width, int height) throws QRCodeGenerationException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        Map<EncodeHintType, ErrorCorrectionLevel> hints = new HashMap<>();
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.H);
        BitMatrix bitMatrix;
        try {
            bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, width, height, hints);
        } catch (WriterException e) {
            throw new QRCodeGenerationException("Error generating QR code");
        }

        ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
        try {
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);
        } catch (IOException e) {
            throw new QRCodeGenerationException("Error writing QR code to output stream");
        }
        return pngOutputStream.toByteArray();
    }
}
