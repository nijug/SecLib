package com.seclib.ipBlocking;

import java.util.concurrent.ConcurrentHashMap;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.HandlerInterceptor;


@Service
public class InMemoryIpBlockService implements IpBlockService, HandlerInterceptor {
    private final ConcurrentHashMap<String, Boolean> blockedIps = new ConcurrentHashMap<>();
    private final BlockedIpRepository blockedIpRepository;

    public InMemoryIpBlockService(BlockedIpRepository blockedIpRepository) {
        this.blockedIpRepository = blockedIpRepository;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull Object handler) {
        String clientIp = request.getRemoteAddr();
        if (isBlocked(clientIp)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }
        return true;
    }

    @Override
    @Transactional
    public void blockIp(String ip) {
        blockedIps.put(ip, Boolean.TRUE);
        blockedIpRepository.save(new BlockedIp(ip));
    }

    @Override
    @Transactional
    public void unblockIp(String ip) {
        blockedIps.remove(ip);
        blockedIpRepository.deleteById(ip);
    }

    public boolean isBlocked(String ip) {
        return blockedIps.containsKey(ip);
    }

    @PostConstruct
    @Transactional
    public void loadBlockedIps() {
        blockedIpRepository.findAll().forEach(blockedIp -> blockedIps.put(blockedIp.getIp(), Boolean.TRUE));
    }
}