package com.seclib.config.session;

import com.seclib.userRoles.service.BaseRoleService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;


@Slf4j
public class SessionFilter implements Filter {

    private final SessionFilterProperties properties;
    private final BaseRoleService<?, ?> roleService;

    public SessionFilter(SessionFilterProperties properties, BaseRoleService<?, ?> roleService) {
        this.properties = properties;
        this.roleService = roleService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (isPreflightRequest(httpRequest)) {
            chain.doFilter(request, response);
            return;
        }

        HttpSession session = httpRequest.getSession(false);

        if (isUserAuthenticated(session)) {
            log.debug("Session exists and userId is present in the session, proceeding with filter chain");
            chain.doFilter(request, response);
        } else {
            handleUnauthenticatedUser(httpRequest, httpResponse, session, chain);
        }
    }

    private boolean isPreflightRequest(HttpServletRequest request) {
        return "OPTIONS".equalsIgnoreCase(request.getMethod());
    }

    private boolean isUserAuthenticated(HttpSession session) {
        return session != null && session.getAttribute("userId") != null;
    }

    private void handleUnauthenticatedUser(HttpServletRequest httpRequest, HttpServletResponse httpResponse, HttpSession session, FilterChain chain) throws IOException, ServletException {
        log.info("Session is null or userId is not present in the session");
        if (properties.isLoginRequired()) {
            redirectToLogin(httpResponse);
        } else {
            assignDefaultRole(httpRequest, session);
            chain.doFilter(httpRequest, httpResponse);
        }
    }

    private void redirectToLogin(HttpServletResponse httpResponse) throws IOException {
        if (properties.isRedirectionEnabled()) {
            log.info("Redirection is enabled, redirecting to: {}", properties.getRedirectionUrl());
            httpResponse.sendRedirect(properties.getRedirectionUrl());
        } else {
            log.info("Redirection is not enabled, sending unauthorized error");
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
        }
    }

    private void assignDefaultRole(HttpServletRequest httpRequest, HttpSession session) {
        if (roleService.isRoleBasedAuthorizationEnabled()) {
            String unauthenticatedUserRoleName = properties.getRoleForUnauthenticatedUsers();
            if (session == null) {
                log.info("Creating new session and setting role to: {}", unauthenticatedUserRoleName);
                session = httpRequest.getSession(true);
                session.setAttribute("role", unauthenticatedUserRoleName);
            }
        }
    }
}
