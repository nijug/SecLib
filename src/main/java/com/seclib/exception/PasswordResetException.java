package com.seclib.exception;

public class PasswordResetException extends ApiException{
    public PasswordResetException(int code, String msg) {
        super(code, msg);
    }
}
