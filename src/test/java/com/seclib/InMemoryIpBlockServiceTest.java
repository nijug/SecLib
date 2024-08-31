package com.seclib;

import com.seclib.ipBlocking.BlockedIpRepository;
import com.seclib.ipBlocking.InMemoryIpBlockService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;

public class InMemoryIpBlockServiceTest {

    @InjectMocks
    private InMemoryIpBlockService ipBlockingService;

    @Mock
    private BlockedIpRepository blockedIpRepository;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void whenIpIsBlocked_thenIsBlockedShouldReturnTrue() {
        String ipToBlock = "192.168.1.100";
        ipBlockingService.blockIp(ipToBlock);

        assertTrue(ipBlockingService.isBlocked(ipToBlock), "IP should be blocked.");
    }

    @Test
    public void whenIpIsUnblocked_thenIsBlockedShouldReturnFalse() {
        String ipToBlock = "192.168.1.100";
        ipBlockingService.blockIp(ipToBlock);
        ipBlockingService.unblockIp(ipToBlock);

        assertFalse(ipBlockingService.isBlocked(ipToBlock), "IP should not be blocked.");
    }

    @Test
    public void whenIpIsNotBlocked_thenIsBlockedShouldReturnFalse() {
        String ipNotBlocked = "192.168.1.101";

        assertFalse(ipBlockingService.isBlocked(ipNotBlocked), "IP should not be blocked.");
    }
}
