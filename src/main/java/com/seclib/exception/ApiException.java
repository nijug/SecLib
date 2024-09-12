package com.seclib.exception;


import lombok.Getter;

@Getter
public class ApiException extends RuntimeException {

    private final int code;

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

}
