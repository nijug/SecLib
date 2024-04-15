package com.seclib.exception;

public class UserException extends ApiException{

    public UserException(int code, String msg) {
        super(code,msg);
    }

}
