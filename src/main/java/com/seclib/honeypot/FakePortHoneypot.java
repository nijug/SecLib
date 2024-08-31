package com.seclib.honeypot;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

@Slf4j
public class FakePortHoneypot implements Honeypot {

    private final int port;
    private ServerSocket serverSocket;
    private Thread listenerThread;
    private volatile boolean running;
    private final HoneypotStrategy honeypotStrategy;
    private final HoneypotStrategyService honeypotStrategyService;

    public FakePortHoneypot(int port, HoneypotStrategyService honeypotStrategyService, HoneypotStrategy honeypotStrategy) {
        this.port = port;
        this.honeypotStrategyService = honeypotStrategyService;
        this.honeypotStrategy = honeypotStrategy;
    }

    @Override
    public void start() {
        running = true;
        listenerThread = new Thread(this::listen);
        listenerThread.start();
        log.info("FakePortHoneypot started on port {}", port);
    }

    private void listen() {
        try {
            serverSocket = new ServerSocket(port);
            while (running) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    logAttempt(clientSocket);
                    clientSocket.close();
                } catch (IOException e) {
                    if (!running) {
                        break;
                    }
                    log.error("Error accepting client connection", e);
                }
            }
        } catch (IOException e) {
            log.error("Could not start FakePortHoneypot on port {}", port, e);
        } finally {
            closeServerSocket();
        }
    }

    @Override
    public void stop() {
        running = false;
        closeServerSocket();
        try {
            if (listenerThread != null) {
                listenerThread.join();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("FakePortHoneypot listener thread interrupted during shutdown", e);
        }
        log.info("FakePortHoneypot stopped on port {}", port);
    }

    private void closeServerSocket() {
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                log.error("Error closing server socket on port {}", port, e);
            }
        }
    }

    private void logAttempt(Socket clientSocket) {
        String clientIP = clientSocket.getInetAddress().getHostAddress();
        honeypotStrategyService.handleHoneypotAccess(clientIP,honeypotStrategy);
    }

    @Override
    public boolean isRunning() {
        return running;
    }
}
