package com.seclib;

import com.seclib.config.csrf.CsrfFilter;
import com.seclib.config.csrf.CsrfFilterProperties;
import com.seclib.csrf.CsrfService;
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
import org.springframework.web.servlet.HandlerMapping;

import static org.mockito.Mockito.mock;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CsrfFilterTests {

    @Mock
    private CsrfService csrfService;

    @Mock
    private CsrfFilterProperties csrfProperties;

    @InjectMocks
    private CsrfFilter csrfFilter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain filterChain;
    private MockHttpSession session;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        session = new MockHttpSession();
        response = new MockHttpServletResponse();
        filterChain = new MockFilterChain();
        request = new MockHttpServletRequest();

        when(csrfProperties.isEnabled()).thenReturn(true);
        when(csrfProperties.getHeaderName()).thenReturn("X-CSRF-TOKEN");
        when(csrfProperties.getRefererDomain()).thenReturn("http://example.com");
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
        // Set CSRF protection to disabled
        when(csrfProperties.isEnabled()).thenReturn(false);

        // Perform a POST request
        request.setMethod("POST");
        request.setSession(session);

        csrfFilter.doFilter(request, response, filterChain);

        // Verify that the filter chain continues without CSRF validation
        verify(csrfService, never()).validateToken(any(HttpSession.class), anyString());
    }

    @Test
    void testCsrfFilterWithInvalidReferer() throws Exception {
        // Set a referer domain
        when(csrfProperties.getRefererDomain()).thenReturn("http://valid-domain.com");

        // Perform a POST request with an invalid referer
        request.setMethod("POST");
        request.addHeader("Referer", "http://invalid-domain.com");
        request.setSession(session);

        csrfFilter.doFilter(request, response, filterChain);

        // Verify that an error is sent due to invalid referer
        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
    }

    @Test
    void testCsrfFilterCreatesNewSessionAndToken() throws Exception {
        // Arrange
        String generatedToken = "newCsrfToken";
        when(csrfService.generateToken()).thenReturn(generatedToken);

        // Act
        csrfFilter.doFilter(request, response, filterChain);

        // Assert
        HttpSession newSession = request.getSession(false);
        assertNotNull(newSession);
        verify(csrfService).generateToken();
        verify(csrfService).storeToken(newSession, generatedToken);
    }

    @Test
    void testCsrfFilterWithSafeMethod() throws Exception {
        // Safe HTTP methods should not require CSRF validation
        request.setMethod("GET");
        csrfFilter.doFilter(request, response, filterChain);

        verify(csrfService, never()).validateToken(any(HttpSession.class), anyString());
    }

    @Test
    void testCsrfFilterWithInvalidToken() throws Exception {
        // Set up an invalid CSRF token scenario
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
        // Set up a missing CSRF token scenario
        request.setMethod("POST");
        request.setSession(session);

        csrfFilter.doFilter(request, response, filterChain);

        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
        verify(csrfService, never()).validateToken(any(HttpSession.class), anyString());
    }

    @Test
    void testCsrfFilterWithValidReferer() throws Exception {
        // Set up a valid referer scenario
        String validReferer = "http://example.com/page";
        when(csrfProperties.getRefererDomain()).thenReturn("http://example.com");

        request.setMethod("POST");
        request.setSession(session);
        request.addHeader("Referer", validReferer);
        csrfFilter.doFilter(request, response, filterChain);
    }

    @Test
    void testCsrfFilterWithMissingReferer() throws Exception {
        // Set up a missing referer scenario
        when(csrfProperties.getRefererDomain()).thenReturn("http://example.com");

        request.setMethod("POST");
        request.setSession(session);

        csrfFilter.doFilter(request, response, filterChain);

        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
    }


    @Test
    void testCsrfFilterWithExistingSessionAndNoTokenCreation() throws Exception {
        // CSRF token creation should not occur if session already exists
        request.setMethod("GET");
        request.setSession(session);
        csrfFilter.doFilter(request, response, filterChain);

        verify(csrfService, never()).generateToken();
        verify(csrfService, never()).storeToken(any(HttpSession.class), anyString());
    }

    @Test
    void testCsrfFilterWithExistingToken() throws Exception {
        // CSRF token validation should occur for unsafe methods when token exists
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
        // CSRF token validation should occur even if no referer domain is configured
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
        // CSRF token validation should occur even if an empty referer domain is configured
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
