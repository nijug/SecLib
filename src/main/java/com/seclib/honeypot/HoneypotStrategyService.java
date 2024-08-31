package com.seclib.honeypot;

import com.seclib.ipBlocking.IpBlockService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class HoneypotStrategyService {

    private final IpBlockService blockService;

    public HoneypotStrategyService(IpBlockService blockService) {
        this.blockService = blockService;
    }

    public void handleHoneypotAccess(String clientIP, HoneypotStrategy strategy) {
        switch (strategy) {
            case STRICT:
                handleStrictStrategy(clientIP);
                break;
            case OBSERVE:
                handleObserveStrategy(clientIP);
                break;
            case DUMMY:
                handleDummyStrategy(clientIP);
                break;
            default:
                log.error("Unknown honeypot strategy: {}", strategy);
                break;
        }
    }

    private void handleDummyStrategy(String clientIP) {
        log.warn("Dummy strategy: Blocking IP {} after accessing honeypot", clientIP);
    }

    private void handleStrictStrategy(String clientIP) {
        log.warn("Strict strategy: Blocking IP {} after accessing honeypot", clientIP);
        blockService.blockIp(clientIP);
    }

    private void handleObserveStrategy(String clientIP) {
        log.warn("Observe strategy: Observing IP {} for further investigation", clientIP);
    }
}
