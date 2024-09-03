package com.seclib.honeypot;

public interface Honeypot {
    void start();
    void stop();

    default void logAttempt(String clientIP, HoneypotStrategy strategy, HoneypotStrategyService strategyService) {
        strategyService.handleHoneypotAccess(clientIP, strategy);
    }
}