package com.seclib.config.session;

import com.seclib.userRoles.service.BaseRoleService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class SessionFilter implements Filter {

    private final SessionFilterProperties properties;
    private final BaseRoleService<?, ?> roleService;
    private static final Logger logger = LoggerFactory.getLogger(SessionFilter.class);

    public SessionFilter(SessionFilterProperties properties, BaseRoleService<?, ?> roleService) {
        this.properties = properties;
        this.roleService = roleService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        HttpSession session = httpRequest.getSession(false);

        if (session == null || session.getAttribute("userId") == null) {
            logger.info("Session is null or userId is not present in the session");
            if (properties.isLoginRequired()) {
                logger.info("Login is required");
                if (properties.isRedirectionEnabled()) {
                    logger.info("Redirection is enabled, redirecting to: " + properties.getRedirectionUrl());
                    httpResponse.sendRedirect(properties.getRedirectionUrl());
                } else {
                    logger.info("Redirection is not enabled, sending unauthorized error");
                    httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                }
            } else {
                if (roleService.isRoleBasedAuthorizationEnabled()) {
                    String unauthenticatedUserRoleName = properties.getRoleForUnauthenticatedUsers();
                    if (session == null) {
                        logger.info("Creating new session and setting role to: " + unauthenticatedUserRoleName);
                        session = httpRequest.getSession(true);
                        session.setAttribute("role", unauthenticatedUserRoleName);
                    }
                }
                logger.info("Proceeding with filter chain");
                chain.doFilter(request, response);
            }
        } else {
            logger.info("Session exists and userId is present in the session, proceeding with filter chain");
            chain.doFilter(request, response);
        }
    }
}