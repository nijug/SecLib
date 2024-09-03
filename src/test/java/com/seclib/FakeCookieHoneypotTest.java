package com.seclib;

import com.seclib.config.HoneypotProperties;
import com.seclib.honeypot.FakeCookieHoneypot;
import com.seclib.honeypot.HoneypotFactory;
import com.seclib.honeypot.HoneypotService;
import com.seclib.honeypot.HoneypotStrategy;
import com.seclib.honeypot.HoneypotStrategyService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class FakeCookieHoneypotTest {

    @Mock
    private HoneypotStrategyService honeypotStrategyService;

    @Mock
    private HoneypotProperties honeypotProperties;

    @Mock
    private HoneypotProperties.FakeCookieHoneypotConfig config;

    @Mock
    private HoneypotFactory honeypotFactory;

    @Mock
    private HoneypotStrategy honeypotStrategy;

    @InjectMocks
    private HoneypotService honeypotService;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    public void setUp() {

        when(config.getName()).thenReturn("fake_session_token");
        when(config.getValue()).thenReturn("unmodifiableValue");

        when(honeypotProperties.isFakeCookies()).thenReturn(true);

        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();

        when(honeypotFactory.createHoneypots(eq("fakecookie"), any(HoneypotProperties.class)))
                .thenReturn(List.of(new FakeCookieHoneypot(honeypotStrategy, honeypotStrategyService, config)));

        honeypotService.startHoneypots();
    }

    @Test
    public void whenCookieIsManipulated_thenBlockRequest() {
        request.setCookies(new Cookie(config.getName(), "manipulatedValue"));

        FakeCookieHoneypot fakeCookieHoneypot = (FakeCookieHoneypot) honeypotService.getActiveHoneypots().get(0);
        boolean result = fakeCookieHoneypot.preHandle(request, response, new Object());

        assertFalse(result);
        verify(honeypotStrategyService).handleHoneypotAccess(anyString(), any());
    }

    @Test
    public void whenCookieIsNotPresent_thenSetFakeCookie() {
        FakeCookieHoneypot fakeCookieHoneypot = (FakeCookieHoneypot) honeypotService.getActiveHoneypots().get(0);
        boolean result = fakeCookieHoneypot.preHandle(request, response, new Object());

        assertTrue(result);
        Cookie cookie = response.getCookie(config.getName());
        assertNotNull(cookie);
        assertEquals(config.getValue(), cookie.getValue());
        assertEquals(config.getPath(), cookie.getPath());
        assertEquals(config.getMaxAge(), cookie.getMaxAge());
        assertEquals(config.isHttpOnly(), cookie.isHttpOnly());
    }

    @Test
    public void whenCookieIsPresentAndValid_thenAllowRequestAndSetFakeCookie() {
        request.setCookies(new Cookie(config.getName(), config.getValue()));
        FakeCookieHoneypot fakeCookieHoneypot = (FakeCookieHoneypot) honeypotService.getActiveHoneypots().get(0);
        boolean result = fakeCookieHoneypot.preHandle(request, response, new Object());

        // Verify that the request is allowed
        assertTrue(result);
        // Verify that the fake cookie is added to the response
        Cookie cookie = response.getCookie(config.getName());
        assertNotNull(cookie);
        assertEquals(config.getValue(), cookie.getValue());
        assertEquals(config.getPath(), cookie.getPath());
        assertEquals(config.getMaxAge(), cookie.getMaxAge());
        assertEquals(config.isHttpOnly(), cookie.isHttpOnly());
    }


}
