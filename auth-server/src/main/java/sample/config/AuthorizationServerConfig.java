/*
 * Copyright 2002-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import java.util.UUID;
import java.util.function.Supplier;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import sample.jose.Jwks;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

/**
 * @author Joe Grandja
 * @author Stefan Ganzer
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults()); // Enable OpenID Connect 1.0

        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login"))
                );

        return http.build();
    }

    // @formatter:off
    @Bean
    RegisteredClientRepository registeredClientRepository() {
        RegisteredClient loginClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("login-client")
                .clientSecret("{noop}secret-login-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/login-client")
                .scope(OidcScopes.OPENID)
                .build();

        RegisteredClient clientA = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-a")
                .clientSecret("{noop}secret-a")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/flow-a")
                .scope("authority-a")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        RegisteredClient clientAB = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-ab")
                .clientSecret("{noop}secret-ab")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/flow-ab")
                .scope("authority-a")
                .scope("authority-b")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        RegisteredClient clientABC = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-abc")
                .clientSecret("{noop}secret-abc")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/flow-abc")
                .scope("authority-a")
                .scope("authority-b")
                .scope("authority-c")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        RegisteredClient clientC = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-c")
                .clientSecret("{noop}secret-c")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("authority-c")
                .build();

        return new InMemoryRegisteredClientRepository(
                loginClient, clientA, clientAB, clientABC, clientC);
    }
    // @formatter:on

    @Bean
    Supplier<JWKSet> jwkSetProvider() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return () -> jwkSet;
    }

    @Bean
    JWKSource<SecurityContext> jwkSource(Supplier<JWKSet> jwkSetProvider) {
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSetProvider.get());
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer("http://auth-server:9000").build();
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().id(UUID.randomUUID().toString());
            }
        };
    }

}