package com.seclib.ipBlocking;

import java.util.concurrent.ConcurrentHashMap;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.springframework.web.servlet.HandlerInterceptor;

public class InMemoryIpBlockService implements IpBlockService, HandlerInterceptor {
    private final ConcurrentHashMap<String, Boolean> blockedIps = new ConcurrentHashMap<>();

    @Override
    public boolean preHandle(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull Object handler) {
        String clientIp = request.getRemoteAddr();
        if (isBlocked(clientIp)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }
        return true;
    }

    public boolean isBlocked(String ip) {
        return blockedIps.containsKey(ip);
    }

    @Override
    public void blockIp(String ip) {
        blockedIps.put(ip, Boolean.TRUE);
    }

    @Override
    public void unblockIp(String ip) {
        blockedIps.remove(ip);
    }
}
