package com.seclib.honeypot;

import com.seclib.config.HoneypotProperties;
import lombok.Getter;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class HoneypotService {

    private final HoneypotProperties honeypotProperties;
    @Getter
    private final List<Honeypot> activeHoneypots;
    private final HoneypotFactory honeypotFactory;

    public HoneypotService(HoneypotProperties honeypotProperties, HoneypotFactory honeypotFactory) {
        this.honeypotProperties = honeypotProperties;
        this.honeypotFactory = honeypotFactory;
        this.activeHoneypots = new ArrayList<>();
    }

    @EventListener(ContextRefreshedEvent.class)
    public void startHoneypots() {
        if (honeypotProperties.isFakePorts()) {
            activeHoneypots.addAll(honeypotFactory.createHoneypots("fakeport", honeypotProperties));

        }

        if (honeypotProperties.isFakeCookies()) {
            activeHoneypots.addAll(honeypotFactory.createHoneypots("fakecookie", honeypotProperties));

        }

        for (Honeypot honeypot : activeHoneypots) {
            honeypot.start();
        }
    }


    @EventListener(ContextClosedEvent.class)
    public void stopHoneypots() {
        for (Honeypot honeypot : activeHoneypots) {
            honeypot.stop();
        }
        activeHoneypots.clear();
    }
}
