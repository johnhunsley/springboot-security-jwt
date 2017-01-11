package com.svlada.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;

/**
 * PasswordEncoderConfig
 * 
 * @author vladimir.stankovic
 *
 * Dec 27, 2016
 */
@Configuration
public class PasswordEncoderConfig {

    @Bean
    protected StandardPasswordEncoder passwordEncoder() {
        return new StandardPasswordEncoder();
    }
}
