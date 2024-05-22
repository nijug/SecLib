package com.seclib.config;

import java.io.IOException;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CorsFilter implements Filter {

    private final CorsProperties corsProperties;

    public CorsFilter(CorsProperties corsProperties) {
        this.corsProperties = corsProperties;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        String[] allowedOrigins = corsProperties.getAllowedOrigins();
        for (String allowedOrigin : allowedOrigins) {
            if (request.getHeader("Origin").equals(allowedOrigin)) {
                response.setHeader("Access-Control-Allow-Origin", allowedOrigin);
                break;
            }
        }

        response.setHeader("Access-Control-Allow-Methods", String.join(",", corsProperties.getAllowedMethods()));
        response.setHeader("Access-Control-Allow-Headers", String.join(",", corsProperties.getAllowedHeaders()));
        response.setHeader("Access-Control-Allow-Credentials", String.valueOf(corsProperties.isAllowCredentials()));

        chain.doFilter(req, res);
    }

    @Override
    public void init(FilterConfig filterConfig) {}

    @Override
    public void destroy() {}
}
