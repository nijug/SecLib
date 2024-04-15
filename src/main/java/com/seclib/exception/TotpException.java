package com.seclib.exception;

public class TotpException extends ApiException{
    public TotpException(int code, String message) {
        super(code, message);
    }
}
