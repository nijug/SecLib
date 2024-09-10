package com.seclib;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;


@SpringBootApplication
@ConfigurationPropertiesScan("com.seclib.config")
public class SecLibApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecLibApplication.class, args);

    }

}
