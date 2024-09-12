package com.seclib.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

@Configuration
public class ArgonConfig {

    @Bean
    public Argon2PasswordEncoder argon2PasswordEncoder() {
        int saltLength = 16;
        int hashLength = 32;
        int parallelism = 1;
        int memory = 19456;
        int iterations = 2;

        return new Argon2PasswordEncoder(saltLength, hashLength, parallelism, memory, iterations);
    }
}