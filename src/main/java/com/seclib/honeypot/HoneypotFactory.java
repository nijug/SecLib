package com.seclib.honeypot;

import com.seclib.config.HoneypotProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Component
public class HoneypotFactory {

    private final HoneypotStrategyService honeypotStrategyService;

    public HoneypotFactory(HoneypotStrategyService honeypotStrategyService) {
        this.honeypotStrategyService = honeypotStrategyService;
    }


    public List<Honeypot> createHoneypots(String type, HoneypotProperties config) {
        return switch (type.toLowerCase()) {
            case "fakeport" -> createFakePortHoneypots(config);
            case "fakecookie" -> createFakeCookieHoneypots(config);
            default -> throw new IllegalArgumentException("Unknown honeypot type: " + type);
        };
    }

    private List<Honeypot> createFakePortHoneypots(HoneypotProperties config) {
        List<Honeypot> honeypots = new ArrayList<>();
        HoneypotStrategy strategy = determineStrategy(
                config.getFakePortStrategy(),
                config.getGlobalStrategy()
        );
        for (Integer port : config.getFakePortHoneypotConfig().getPorts()) {
            honeypots.add(new FakePortHoneypot(port, honeypotStrategyService, strategy));
        }
        return honeypots;
    }

    private List<Honeypot> createFakeCookieHoneypots(HoneypotProperties config) {
        List<Honeypot> honeypots = new ArrayList<>();
        HoneypotStrategy strategy = determineStrategy(
                config.getFakeCookieStrategy(),
                config.getGlobalStrategy()
        );
        for (HoneypotProperties.FakeCookieHoneypotConfig fakeCookieHoneypotConfig : config.getFakeCookieHoneypotConfig()) {
            honeypots.add(new FakeCookieHoneypot(strategy, honeypotStrategyService, fakeCookieHoneypotConfig));
        }

        return honeypots;
    }

    private HoneypotStrategy determineStrategy(Optional<HoneypotStrategy> specificStrategy, HoneypotStrategy globalStrategy) {
        return specificStrategy.orElse(globalStrategy);
    }

}
