package com.seclib;

import com.seclib.config.HoneypotProperties;
import com.seclib.honeypot.FakeCookieHoneypot;
import com.seclib.honeypot.HoneypotStrategy;
import com.seclib.honeypot.HoneypotStrategyService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class FakeCookieHoneypotTest {

    @Mock
    private HoneypotStrategyService honeypotStrategyService;

    @Mock
    private HoneypotProperties.FakeCookieHoneypotConfig config;

    @InjectMocks
    private FakeCookieHoneypot fakeCookieHoneypot;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        // Set up the configuration for the fake cookie
        when(config.getName()).thenReturn("fake_session_token");
        when(config.getValue()).thenReturn("unmodifiableValue");
        when(config.isHttpOnly()).thenReturn(true);
        when(config.getPath()).thenReturn("/");
        when(config.getMaxAge()).thenReturn(86400);

        // Initialize request and response mocks
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();

        // Start the honeypot
        fakeCookieHoneypot.start();
    }

    @Test
    public void whenCookieIsManipulated_thenBlockRequest() {
        // Set up a manipulated cookie in the request
        request.setCookies(new Cookie(config.getName(), "manipulatedValue"));

        // Call preHandle and expect the request to be blocked
        boolean result = fakeCookieHoneypot.preHandle(request, response, new Object());

        // Verify that the request is blocked
        assertFalse(result);
        // Verify that the honeypot strategy service is called
        verify(honeypotStrategyService).handleHoneypotAccess(anyString(), any(HoneypotStrategy.class));
    }

    @Test
    public void whenCookieIsNotPresent_thenSetFakeCookie() {
        // Call preHandle without any cookies set in the request
        boolean result = fakeCookieHoneypot.preHandle(request, response, new Object());

        // Verify that the request is not blocked
        assertTrue(result);
        // Verify that the fake cookie is added to the response
        Cookie cookie = response.getCookie(config.getName());
        assertNotNull(cookie);
        assertEquals(config.getValue(), cookie.getValue());
        assertEquals(config.getPath(), cookie.getPath());
        assertEquals(config.getMaxAge(), cookie.getMaxAge());
        assertEquals(config.isHttpOnly(), cookie.isHttpOnly());
    }

    // Additional tests can be written for other scenarios, such as when the honeypot is not running
}
