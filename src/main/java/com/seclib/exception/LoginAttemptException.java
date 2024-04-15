package com.seclib.exception;

public class LoginAttemptException extends ApiException{

    public LoginAttemptException(int code, String msg) {
        super(code,msg);
    }
}
