package com.seclib.exception;

public class OAuthException extends ApiException {
    public OAuthException(int code, String msg) {
        super(code, msg);
    }
}
