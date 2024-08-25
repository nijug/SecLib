package com.seclib.config.csrf;

import com.seclib.csrf.CsrfService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

public class CsrfFilter implements Filter {

    private final CsrfService csrfService;
    private final CsrfFilterProperties csrfProperties;

    public CsrfFilter( CsrfFilterProperties csrfProperties, CsrfService csrfService) {
        this.csrfProperties = csrfProperties;
        this.csrfService = csrfService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;


        if ("POST".equals(httpRequest.getMethod()) || "PUT".equals(httpRequest.getMethod()) ||
                "DELETE".equals(httpRequest.getMethod()) || "PATCH".equals(httpRequest.getMethod())) {

            String requestToken = httpRequest.getHeader(csrfProperties.getHeaderName());

            HttpSession session = httpRequest.getSession(false);

            if (!csrfService.validateToken(session, requestToken)) {
                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid CSRF token");
                return;
            }

            if (csrfProperties.getRefererDomain() != null && !csrfProperties.getRefererDomain().isEmpty()) {
                String refererHeader = httpRequest.getHeader("Referer");
                if (refererHeader == null || !refererHeader.startsWith(csrfProperties.getRefererDomain())) {
                    httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid Referer header");
                    return;
                }
            }
        }

        if (httpRequest.getSession(false) == null) {
            HttpSession newSession = httpRequest.getSession(true);
            String newToken = csrfService.generateToken();
            csrfService.storeToken(newSession, newToken);
        }

        chain.doFilter(request, response);
    }
}
