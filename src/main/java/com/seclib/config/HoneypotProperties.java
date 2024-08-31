package com.seclib.config;

import com.seclib.honeypot.HoneypotStrategy;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Optional;

@Data
@Configuration
@Validated
@ConfigurationProperties(prefix = "honeypot")
public class HoneypotProperties {

    private HoneypotStrategy globalStrategy = HoneypotStrategy.STRICT;
    private boolean fakePorts = false;
    private HoneypotConfig config;

    @Data
    public static class HoneypotConfig {

        private List<Integer> ports;
        private Optional<HoneypotStrategy> fakePortStrategy = Optional.empty();
    }
}
