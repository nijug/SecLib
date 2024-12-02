package com.seclib;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.ComponentScan;

@ComponentScan(basePackages = {"com.seclib"})
@EnableAutoConfiguration
@ConfigurationPropertiesScan("com.seclib.config")
public class SecLibConfiguration {

}
