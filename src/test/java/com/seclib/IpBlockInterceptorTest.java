package com.seclib;

import com.seclib.ipBlocking.InMemoryIpBlockService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import static org.junit.jupiter.api.Assertions.*;

public class IpBlockInterceptorTest {

    private InMemoryIpBlockService ipBlockService;

    @BeforeEach
    public void setUp() {
        ipBlockService = new InMemoryIpBlockService();
    }

    @Test
    public void whenIpIsBlocked_thenRequestIsInterceptedAndForbidden() {
        String blockedIp = "192.168.1.100";
        ipBlockService.blockIp(blockedIp);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(blockedIp);
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertFalse(ipBlockService.preHandle(request, response, new Object()));
        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
    }

    @Test
    public void whenIpIsNotBlocked_thenRequestIsNotIntercepted() {
        String allowedIp = "192.168.1.101";

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(allowedIp);
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertTrue(ipBlockService.preHandle(request, response, new Object()));
    }
}
