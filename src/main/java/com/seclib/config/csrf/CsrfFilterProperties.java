package com.seclib.config.csrf;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Data
@Validated
@ConfigurationProperties(prefix = "csrf")
public class CsrfFilterProperties {

    private boolean enabled = false;
    @NotBlank
    private String secret= "secret";
    @NotBlank
    private String headerName = "X-CSRF-TOKEN";
    @NotBlank
    private String parameterName = "_csrf";
    private String refererDomain;

}
