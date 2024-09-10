package com.seclib.config.csrf;

import com.seclib.csrf.CsrfService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.io.IOException;

@Slf4j
public class CsrfFilter implements Filter {

    private final CsrfService csrfService;
    private final CsrfFilterProperties csrfProperties;
    private final RequestMappingHandlerMapping handlerMapping;

    public CsrfFilter(CsrfFilterProperties csrfProperties, CsrfService csrfService, RequestMappingHandlerMapping handlerMapping) {
        this.csrfProperties = csrfProperties;
        this.csrfService = csrfService;
        this.handlerMapping = handlerMapping;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        log.info("Processing request for path: {}", httpRequest.getRequestURI());

        if (isPreflightRequest(httpRequest)) {
            log.info("Recognized preflight OPTIONS request, skipping CSRF check");
            chain.doFilter(request, response);
            return;
        }

        if (shouldBypassCsrfCheck(httpRequest)) {
            log.info("CSRF check bypassed for this request");
            chain.doFilter(request, response);
            return;
        }

        if (isCsrfProtectionRequired(httpRequest)) {
            log.info("CSRF protection required for this request");
            if (!isCsrfTokenValid(httpRequest)) {
                log.warn("Invalid CSRF token for request");
                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid CSRF token");
                return;
            }
        }

        if (isRefererCheckRequired()) {
            log.info("Referer check required for this request");
            if (!isRefererValid(httpRequest)) {
                log.warn("Invalid Referer header for request");
                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid Referer header");
                return;
            }
        }

        ensureSessionExists(httpRequest);
        chain.doFilter(request, response);
    }

    private boolean isPreflightRequest(HttpServletRequest request) {
        return "OPTIONS".equalsIgnoreCase(request.getMethod());
    }

    private boolean isCsrfProtectionRequired(HttpServletRequest request) {
        return "POST".equals(request.getMethod()) || "PUT".equals(request.getMethod()) ||
                "DELETE".equals(request.getMethod()) || "PATCH".equals(request.getMethod());
    }

    private boolean isCsrfTokenValid(HttpServletRequest request) {
        String requestToken = request.getHeader(csrfProperties.getHeaderName());
        HttpSession session = request.getSession(false);
        return csrfService.validateToken(session, requestToken);
    }

    private boolean isRefererCheckRequired() {
        return csrfProperties.getRefererDomain() != null && !csrfProperties.getRefererDomain().isEmpty();
    }

    private boolean isRefererValid(HttpServletRequest request) {
        String refererHeader = request.getHeader("Referer");
        return refererHeader != null && refererHeader.startsWith(csrfProperties.getRefererDomain());
    }

    private void ensureSessionExists(HttpServletRequest request) {
        if (request.getSession(false) == null) {
            log.info("No session exists, creating a new session and generating CSRF token");
            HttpSession newSession = request.getSession(true);
            String newToken = csrfService.generateToken();
            csrfService.storeToken(newSession, newToken);
            log.info("New CSRF token generated and stored in session");
        } else {
            log.info("Session already exists, no need to create a new one");
        }
    }


    private boolean shouldBypassCsrfCheck(HttpServletRequest request) {
        try {
            HandlerExecutionChain handlerExecutionChain = handlerMapping.getHandler(request);
            if (handlerExecutionChain != null) {
                Object handler = handlerExecutionChain.getHandler();
                if (handler instanceof HandlerMethod handlerMethod) {
                    CsrfBypass csrfBypassAnnotation = handlerMethod.getMethodAnnotation(CsrfBypass.class);
                    return csrfBypassAnnotation != null;
                }
            }
        } catch (Exception e) {
            log.error("Exception occurred during CSRF check bypass", e);
        }
        return false;
    }
}
