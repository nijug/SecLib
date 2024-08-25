package com.seclib.config.csrf;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Setter
@Getter
@Configuration
@ConfigurationProperties(prefix = "csrf")
public class CsrfFilterProperties {

    private boolean enabled = false;
    private String secret= "secret";
    private String headerName = "X-CSRF-TOKEN";
    private String parameterName = "_csrf";
    private String refererDomain;

}
