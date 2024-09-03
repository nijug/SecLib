package com.seclib.honeypot;

import com.seclib.config.HoneypotProperties;
import jakarta.annotation.PostConstruct;
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
        System.out.println("HoneypotService created");
    }

    @PostConstruct
    public void startHoneypots() {
        System.out.println("Starting honeypots");
        if (honeypotProperties.isFakePorts()) {
            System.out.println("Creating fake ports");
            activeHoneypots.addAll(honeypotFactory.createHoneypots("fakeport", honeypotProperties));

        }

        if (honeypotProperties.isFakeCookies()) {
            System.out.println("Creating fake cookies");
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
