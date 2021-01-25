/*
 * Copyright 2002-2021 the original author or authors.
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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerSecurity;
import org.springframework.security.crypto.keys.KeyManager;
import org.springframework.security.crypto.keys.StaticKeyGeneratingKeyManager;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Joe Grandja
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerSecurity.applyDefaultConfiguration(http);
        return http.build();
    }

    // @formatter:off
    @Bean
    RegisteredClientRepository registeredClientRepository() {
        RegisteredClient loginClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("login-client")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/login/oauth2/code/login-client")
                .scope(OidcScopes.OPENID)
                .build();

        RegisteredClient clientA = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-a")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/flow-a")
                .scope("authority-a")
                .clientSettings(clientSettings -> clientSettings.requireUserConsent(true))
                .build();

        RegisteredClient clientAB = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-ab")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/flow-ab")
                .scope("authority-a")
                .scope("authority-b")
                .clientSettings(clientSettings -> clientSettings.requireUserConsent(true))
                .build();

        RegisteredClient clientABC = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-abc")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/flow-abc")
                .scope("authority-a")
                .scope("authority-b")
                .scope("authority-c")
                .clientSettings(clientSettings -> clientSettings.requireUserConsent(true))
                .build();

        RegisteredClient clientC = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-c")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("authority-c")
                .build();

        return new InMemoryRegisteredClientRepository(
                loginClient, clientA, clientAB, clientABC, clientC);
    }
    // @formatter:on

    @Bean
    KeyManager keyManager() {
        return new StaticKeyGeneratingKeyManager();
    }

}