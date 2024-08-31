package com.seclib.ipBlocking;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class IpBlockConfiguration {

    private final BlockedIpRepository blockedIpRepository;

    public IpBlockConfiguration(BlockedIpRepository blockedIpRepository) {
        this.blockedIpRepository = blockedIpRepository;
    }

    @Bean
    @ConditionalOnMissingBean(IpBlockService.class)
    public IpBlockService inMemoryIpBlockingService() {
        return new InMemoryIpBlockService(blockedIpRepository);
    }
}

/*
@Configuration
public class CustomIpBlockingConfiguration {

    @Bean
    public IpBlockService amazonIpBlockingService() {
        // Configuration for AmazonIpBlockingService
        return new AmazonIpBlockingService();
        }
        }
 */