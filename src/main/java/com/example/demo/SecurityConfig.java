package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SecurityConfig {

  @Autowired
  private ClientRegistrationRepository clientRegistrationRepository;

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        .anyRequest().authenticated()
        .and()
        .oauth2Login(oauth2Login ->
            oauth2Login
                .authorizationEndpoint(authorizationEndpointConfig ->
                authorizationEndpointConfig.authorizationRequestResolver(new CustomAuthorizationRequestResolver(
                    this.clientRegistrationRepository)))
        );
    return http.build();
  }
}
