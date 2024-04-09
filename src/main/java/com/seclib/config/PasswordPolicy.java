package com.seclib.config;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class PasswordPolicy {
    private String pattern;
    private int entropy;
}