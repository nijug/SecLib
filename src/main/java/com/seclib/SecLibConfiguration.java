package com.seclib;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@ComponentScan(basePackages = {"com.seclib"})
@EnableAutoConfiguration
@ConfigurationPropertiesScan("com.seclib.config")
public class SecLibConfiguration {

}
