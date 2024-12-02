package com.springframework.careerconnectauthserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Set;
import java.util.stream.Collectors;

@Configuration
public class CustomClaimsConfiguration {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().claims(claims -> {
                    Authentication authentication = context.getPrincipal();
                    Set<String> roles = authentication.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .map(c -> c.replaceFirst("^ROLE_", ""))
                            .collect(Collectors.toSet());

                    claims.put("sub", authentication.getName());
                    claims.put("email", authentication.getName());
                    claims.put("roles", "ROLE_ADMIN");
                });
            }
        };
    }
}
