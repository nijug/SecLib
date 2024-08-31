package com.seclib.honeypot;

public interface Honeypot {
    void start();
    void stop();
    boolean isRunning();
}