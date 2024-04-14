package com.seclib.exception;


public class ApiException extends RuntimeException {

    private int code;

    public ApiException(int code, String msg) {
        super(msg);
        this.code = code;
    }

    @Override
    public String toString() {
        return "ApiException{" +
                "code=" + code +
                ", message=" + getMessage() +
                '}';
    }

    public int getCode() {
        return code;
    }
}
