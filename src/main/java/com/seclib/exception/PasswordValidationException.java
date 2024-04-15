package com.seclib.exception;

public class PasswordValidationException extends ApiException{

        public PasswordValidationException(int code, String msg) {
            super(code,msg);
        }
}
