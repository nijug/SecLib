package com.seclib.exception;

public class QRCodeGenerationException extends ApiException{
        public QRCodeGenerationException(String msg) {
            super(500, msg);
        }
}
