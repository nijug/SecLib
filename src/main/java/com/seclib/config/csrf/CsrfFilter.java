package com.seclib.config.csrf;

import com.seclib.csrf.CsrfService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.io.IOException;

public class CsrfFilter implements Filter {

    private final CsrfService csrfService;
    private final CsrfFilterProperties csrfProperties;
    private static final Logger logger = LoggerFactory.getLogger(CsrfFilter.class);
    private final RequestMappingHandlerMapping handlerMapping;

    public CsrfFilter(CsrfFilterProperties csrfProperties, CsrfService csrfService, RequestMappingHandlerMapping handlerMapping) {
        this.csrfProperties = csrfProperties;
        this.csrfService = csrfService;
        this.handlerMapping = handlerMapping;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;

        if ("OPTIONS".equalsIgnoreCase(httpRequest.getMethod())) {
            logger.info("Recognized preflight request, proceeding with filter chain");
            chain.doFilter(request, response);
            return;
        }

        if (shouldBypassCsrfCheck(httpRequest)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletResponse httpResponse = (HttpServletResponse) response;


        if ("POST".equals(httpRequest.getMethod()) || "PUT".equals(httpRequest.getMethod()) ||
                "DELETE".equals(httpRequest.getMethod()) || "PATCH".equals(httpRequest.getMethod())) {

            String requestToken = httpRequest.getHeader(csrfProperties.getHeaderName());

            HttpSession session = httpRequest.getSession(false);

            logger.info("CSRF token from request: {}", requestToken);
            logger.info("CSRF token from session: {}", csrfService.getToken(session));

            if (!csrfService.validateToken(session, requestToken)) {
                logger.warn("Invalid CSRF token for session ID: {}", session.getId());
                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid CSRF token");
                return;
            }

            if (csrfProperties.getRefererDomain() != null && !csrfProperties.getRefererDomain().isEmpty()) {
                String refererHeader = httpRequest.getHeader("Referer");
                logger.info("Referer header from request: {}", refererHeader);
                if (refererHeader == null || !refererHeader.startsWith(csrfProperties.getRefererDomain())) {
                    logger.warn("Invalid Referer header: {}", refererHeader);
                    httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid Referer header");
                    return;
                }
            }
        }

        if (httpRequest.getSession(false) == null) {
            logger.info("Creating new session and generating new CSRF token");
            HttpSession newSession = httpRequest.getSession(true);
            String newToken = csrfService.generateToken();
            csrfService.storeToken(newSession, newToken);
        }
        chain.doFilter(request, response);
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
                else {
                    logger.info("Handler not recognized");
                }
            }
        } catch (Exception e) {
            logger.info("Exception occurred during CSRF check bypass", e);
        }
        return false;
    }

}
