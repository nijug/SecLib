package com.seclib.config.csp;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@Data
@ConfigurationProperties(prefix = "csp")
class CspFilterProperties {
    private List<String> directives;
}
