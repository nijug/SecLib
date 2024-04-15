package com.seclib.exception;

public class TwoFAuthException extends ApiException{

    public TwoFAuthException(int code, String msg) {
        super(code,msg);
    }
}
