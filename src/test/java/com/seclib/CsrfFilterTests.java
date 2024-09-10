package com.seclib;

import com.seclib.config.csrf.CsrfFilter;
import com.seclib.config.csrf.CsrfFilterProperties;
import com.seclib.csrf.CsrfService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import static org.mockito.Mockito.mock;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CsrfFilterTests {

    @Mock
    private CsrfService csrfService;

    @Mock
    private CsrfFilterProperties csrfProperties;

    @Mock
    private RequestMappingHandlerMapping handlerMapping;

    @InjectMocks
    private CsrfFilter csrfFilter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain filterChain;
    private MockHttpSession session;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        session = new MockHttpSession();
        response = new MockHttpServletResponse();
        filterChain = new MockFilterChain();
        request = new MockHttpServletRequest();

        when(csrfProperties.isEnabled()).thenReturn(true);
        when(csrfProperties.getHeaderName()).thenReturn("X-CSRF-TOKEN");
        when(csrfProperties.getRefererDomain()).thenReturn("http://example.com");
        when(handlerMapping.getHandler(any(HttpServletRequest.class)))
                .thenReturn(new HandlerExecutionChain(new Object()));
        HandlerMethod mockHandlerMethod = mock(HandlerMethod.class);
        request.setAttribute(HandlerMapping.BEST_MATCHING_HANDLER_ATTRIBUTE, mockHandlerMethod);
    }

    @Test
    void testCsrfFilterWithValidToken() throws Exception {
        String csrfToken = "validCsrfToken";
        session.setAttribute("CSRF_TOKEN", csrfToken);

        request.setMethod("POST");
        request.addHeader(csrfProperties.getHeaderName(), csrfToken);
        request.setSession(session);

        when(csrfService.validateToken(any(HttpSession.class), eq(csrfToken))).thenReturn(true);

        csrfFilter.doFilter(request, response, filterChain);

        verify(csrfService).validateToken(any(HttpSession.class), eq(csrfToken));
    }

    @Test
    void testCsrfFilterDisabled() throws Exception {
        when(csrfProperties.isEnabled()).thenReturn(false);

        request.setMethod("POST");
        request.setSession(session);

        csrfFilter.doFilter(request, response, filterChain);

        verify(csrfService, never()).validateToken(any(HttpSession.class), anyString());
    }

    @Test
    void testCsrfFilterWithInvalidReferer() throws Exception {
        when(csrfProperties.getRefererDomain()).thenReturn("http://valid-domain.com");

        request.setMethod("POST");
        request.addHeader("Referer", "http://invalid-domain.com");
        request.setSession(session);

        csrfFilter.doFilter(request, response, filterChain);

        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
    }


    @Test
    void testCsrfFilterWithSafeMethod() throws Exception {
        request.setMethod("GET");
        csrfFilter.doFilter(request, response, filterChain);

        verify(csrfService, never()).validateToken(any(HttpSession.class), anyString());
    }

    @Test
    void testCsrfFilterWithInvalidToken() throws Exception {
        String invalidCsrfToken = "invalidCsrfToken";
        session.setAttribute("CSRF_TOKEN", "validCsrfToken");
        request.setMethod("POST");
        request.addHeader(csrfProperties.getHeaderName(), invalidCsrfToken);
        request.setSession(session);

        when(csrfService.validateToken(any(HttpSession.class), eq(invalidCsrfToken))).thenReturn(false);

        csrfFilter.doFilter(request, response, filterChain);

        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
        verify(csrfService).validateToken(any(HttpSession.class), eq(invalidCsrfToken));
    }

    @Test
    void testCsrfFilterWithMissingToken() throws Exception {
        request.setMethod("POST");
        request.setSession(session);

        csrfFilter.doFilter(request, response, filterChain);

        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
        verify(csrfService, never()).validateToken(any(HttpSession.class), anyString());
    }

    @Test
    void testCsrfFilterWithValidReferer() throws Exception {
        String validReferer = "http://example.com/page";
        when(csrfProperties.getRefererDomain()).thenReturn("http://example.com");

        request.setMethod("POST");
        request.setSession(session);
        request.addHeader("Referer", validReferer);
        csrfFilter.doFilter(request, response, filterChain);
    }

    @Test
    void testCsrfFilterWithMissingReferer() throws Exception {
        when(csrfProperties.getRefererDomain()).thenReturn("http://example.com");

        request.setMethod("POST");
        request.setSession(session);

        csrfFilter.doFilter(request, response, filterChain);

        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
    }


    @Test
    void testCsrfFilterWithExistingSessionAndNoTokenCreation() throws Exception {
        request.setMethod("GET");
        request.setSession(session);
        csrfFilter.doFilter(request, response, filterChain);

        verify(csrfService, never()).generateToken();
        verify(csrfService, never()).storeToken(any(HttpSession.class), anyString());
    }

    @Test
    void testCsrfFilterWithExistingToken() throws Exception {
        String csrfToken = "existingCsrfToken";
        session.setAttribute("CSRF_TOKEN", csrfToken);
        request.setMethod("POST");
        request.addHeader(csrfProperties.getHeaderName(), csrfToken);
        request.setSession(session);

        when(csrfService.validateToken(session, csrfToken)).thenReturn(true);

        csrfFilter.doFilter(request, response, filterChain);

        verify(csrfService).validateToken(session, csrfToken);
    }

    @Test
    void testCsrfFilterWithNoRefererDomainConfigured() throws Exception {
        when(csrfProperties.getRefererDomain()).thenReturn(null);

        String csrfToken = "csrfToken";
        session.setAttribute("CSRF_TOKEN", csrfToken);
        request.setMethod("POST");
        request.addHeader(csrfProperties.getHeaderName(), csrfToken);
        request.setSession(session);

        when(csrfService.validateToken(session, csrfToken)).thenReturn(true);

        csrfFilter.doFilter(request, response, filterChain);

        verify(csrfService).validateToken(session, csrfToken);
    }

    @Test
    void testCsrfFilterWithEmptyRefererDomainConfigured() throws Exception {
        when(csrfProperties.getRefererDomain()).thenReturn("");

        String csrfToken = "csrfToken";
        session.setAttribute("CSRF_TOKEN", csrfToken);
        request.setMethod("POST");
        request.addHeader(csrfProperties.getHeaderName(), csrfToken);
        request.setSession(session);

        when(csrfService.validateToken(session, csrfToken)).thenReturn(true);

        csrfFilter.doFilter(request, response, filterChain);

        verify(csrfService).validateToken(session, csrfToken);
    }

}
