package com.seclib;

import com.seclib.config.HoneypotProperties;
import com.seclib.honeypot.Honeypot;
import com.seclib.honeypot.HoneypotFactory;
import com.seclib.honeypot.HoneypotService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
public class HoneypotServiceTest {

    @Mock
    private HoneypotProperties honeypotProperties;

    @Mock
    private HoneypotProperties.HoneypotConfig honeypotConfig;

    @Mock
    private HoneypotFactory honeypotFactory;

    @Mock
    private Honeypot fakePortHoneypot;

    @InjectMocks
    private HoneypotService honeypotService;

    @BeforeEach
    public void setUp() {

        when(honeypotProperties.isFakePorts()).thenReturn(true);

        when(honeypotFactory.createHoneypot(eq("fakeport"), any(HoneypotProperties.class)))
                .thenReturn(List.of(fakePortHoneypot));

    }

    @Test
    public void whenContextRefreshedEvent_thenStartHoneypots() {
        honeypotService.startHoneypots();

        verify(honeypotFactory).createHoneypot(eq("fakeport"), any(HoneypotProperties.class));
        verify(fakePortHoneypot, times(1)).start(); // Should be called once for each port
        assertEquals(1, honeypotService.getActiveHoneypots().size());
    }

    @Test
    public void whenContextClosedEvent_thenStopHoneypots() {
        honeypotService.startHoneypots();
        honeypotService.stopHoneypots();

        verify(fakePortHoneypot).stop();
        assertTrue(honeypotService.getActiveHoneypots().isEmpty());
    }
}
