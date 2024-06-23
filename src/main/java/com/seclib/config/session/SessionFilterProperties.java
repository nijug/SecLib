package com.seclib.config.session;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Data
@Component
@ConfigurationProperties(prefix = "session.filter")
public class SessionFilterProperties {
    private boolean loginRequired;
    private String roleForUnauthenticatedUsers;
    private boolean redirectionEnabled;
    private String redirectionUrl;
}