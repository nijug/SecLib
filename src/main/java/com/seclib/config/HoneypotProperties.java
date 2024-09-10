package com.seclib.config;

import com.seclib.honeypot.HoneypotStrategy;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Optional;

@Data
@Validated
@ConfigurationProperties(prefix = "honeypot")
public class HoneypotProperties {

    private HoneypotStrategy globalStrategy = HoneypotStrategy.STRICT;
    private Optional<HoneypotStrategy> fakePortStrategy = Optional.empty();
    private Optional<HoneypotStrategy> fakeCookieStrategy = Optional.empty();
    private boolean fakePorts = false;
    private boolean fakeCookies = false;
    private FakePortHoneypotConfig fakePortHoneypotConfig;
    private List<FakeCookieHoneypotConfig> fakeCookieHoneypotConfig;

    @Data
    public static class FakePortHoneypotConfig {
        private List<Integer> ports;
    }

    @Data
    public static class FakeCookieHoneypotConfig {
        @NotBlank
        private String name = "roles_info";
        @NotBlank
        private String value = "Z3Vlc3Q7ZXhwaXJlcz1XZWQsIDMxIERlYyAyMDI1IDIzOjU5OjU5IEdNVA==";
        private boolean httpOnly = true;
        @NotBlank
        private String path = "/";
        private int maxAge = 24 * 60 * 60;
    }
}
