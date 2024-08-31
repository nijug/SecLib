package com.seclib.honeypot;

import com.seclib.config.HoneypotProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class HoneypotFactory  {

    private final HoneypotStrategyService honeypotStrategyService;

    public HoneypotFactory(HoneypotStrategyService honeypotStrategyService) {
        this.honeypotStrategyService = honeypotStrategyService;
    }


    public List<Honeypot> createHoneypot(String type, HoneypotProperties config) {
        switch (type.toLowerCase()) {
            case "fakeport":
                List<Honeypot> honeypots = new ArrayList<>();
                HoneypotStrategy currentStrategy = config.getGlobalStrategy();
                if (config.getConfig().getFakePortStrategy().isPresent())
                {
                    currentStrategy= config.getConfig().getFakePortStrategy().get();
                }
                for (Integer port : config.getConfig().getPorts()) {
                    honeypots.add(createFakePortHoneypot(port, currentStrategy));
                }
                return honeypots;

            default:
                throw new IllegalArgumentException("Unknown honeypot type: " + type);
        }
    }

    private Honeypot createFakePortHoneypot(Integer port, HoneypotStrategy strategy) {
        return new FakePortHoneypot(port, honeypotStrategyService, strategy);
    }

}
