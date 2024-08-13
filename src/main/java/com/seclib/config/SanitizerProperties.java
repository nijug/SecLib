package com.seclib.config;

import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import org.springframework.validation.annotation.Validated;

import java.util.List;

@Getter
@Configuration
@Validated
@ConfigurationProperties(prefix = "sanitizer")
public class SanitizerProperties {

    private final List<String> allowedElements;
    private final List<String> allowedAttributes;
    private final List<String> allowedProtocols;

    public SanitizerProperties(List<String> allowedElements, List<String> allowedAttributes, List<String> allowedProtocols) {
        this.allowedElements = allowedElements;
        this.allowedAttributes = allowedAttributes;
        this.allowedProtocols = allowedProtocols;
    }

}
