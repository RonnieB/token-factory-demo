package com.example.tokenfactory;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.net.URLEncoder;

/**
 * /tokens and /refresh are open (they hand out tokens); everything else needs a valid JWT.
 * Two non-default touches keep the client trivial:
 *   - the access token is read from a cookie instead of the Authorization header, so the
 *     browser resends it automatically;
 *   - a missing or expired token yields a 302 to /refresh instead of a 401, so the client
 *     just follows the redirect.
 */
@Configuration
public class SecurityConfig {

    @Bean
    BearerTokenResolver cookieBearerTokenResolver() {
        return request -> Cookies.read(request, Cookies.ACCESS_TOKEN).orElse(null);
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, BearerTokenResolver bearerTokenResolver) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/tokens", "/refresh").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .bearerTokenResolver(bearerTokenResolver)
                        .jwt(jwt -> {})
                        .authenticationEntryPoint((request, response, ex) -> {
                            String target = UriComponentsBuilder.fromPath("/refresh")
                                    .queryParam("redirect", URLEncoder.encode(
                                            request.getRequestURI(), StandardCharsets.UTF_8))
                                    .build().toUriString();
                            response.sendRedirect(target);
                        }))
                .build();
    }
}
