package com.seclib.honeypot;

import com.seclib.config.HoneypotProperties;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Slf4j
public class FakeCookieHoneypot implements Honeypot, HandlerInterceptor {

    private final HoneypotStrategy honeypotStrategy;
    private final HoneypotStrategyService honeypotStrategyService;
    private final HoneypotProperties.FakeCookieHoneypotConfig config;
    @Getter
    private volatile boolean running;

    public FakeCookieHoneypot(HoneypotStrategy honeypotStrategy, HoneypotStrategyService honeypotStrategyService, HoneypotProperties.FakeCookieHoneypotConfig config) {
        this.honeypotStrategy = honeypotStrategy;
        this.honeypotStrategyService = honeypotStrategyService;
        this.config = config;
    }

    @Override
    public void start() {
        running = true;
        log.info("FakeCookieHoneypot started");
    }

    @Override
    public void stop() {
        running = false;
        log.info("FakeCookieHoneypot stopped");
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!running) {
            return true;
        }

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (config.getName().equals(cookie.getName()) && !config.getValue().equals(cookie.getValue())) {
                    logAttempt(request.getRemoteAddr(), honeypotStrategy, honeypotStrategyService);
                    return false;
                }
            }
        }

        setFakeCookie(response);

        return true;
    }


    private void setFakeCookie(HttpServletResponse response) {
        Cookie fakeCookie = new Cookie(config.getName(), config.getValue());
        fakeCookie.setHttpOnly(config.isHttpOnly());
        fakeCookie.setPath(config.getPath());
        fakeCookie.setMaxAge(config.getMaxAge()); // Set the cookie to expire in 24 hours
        response.addCookie(fakeCookie);
    }
}