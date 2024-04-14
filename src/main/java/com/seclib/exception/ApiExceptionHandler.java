package com.seclib.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<String> handleApiException(ApiException ex) {
        System.out.println(ex.toString());
        return ResponseEntity.status(ex.getCode()).body(ex.getMessage());
    }

}