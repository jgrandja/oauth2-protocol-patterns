/*
 * Copyright 2002-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.ResourceUtils;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.util.Arrays;

/**
 * @author Joe Grandja
 */
@Configuration
public class RestTemplateConfig {
    private static final String KEYSTORE_TYPE = "pkcs12";
    private static final String KEYSTORE_PATH = "classpath:keycloak-client.p12";
    private static final String KEYSTORE_PASSWORD = "secret";

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) throws Exception {
        SSLContext sslContext = SSLContextBuilder.create()
                .setKeyStoreType(KEYSTORE_TYPE)
                .loadKeyMaterial(
                        ResourceUtils.getFile(KEYSTORE_PATH),
                        KEYSTORE_PASSWORD.toCharArray(),
                        KEYSTORE_PASSWORD.toCharArray())
                .loadTrustMaterial(
                        ResourceUtils.getFile(KEYSTORE_PATH),
                        KEYSTORE_PASSWORD.toCharArray())
//                .loadTrustMaterial(TrustSelfSignedStrategy.INSTANCE)
                .build();

        HttpClient client = HttpClients.custom()
                .setSSLContext(sslContext)
                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .build();

        return builder
                .requestFactory(() -> new HttpComponentsClientHttpRequestFactory(client))
                .messageConverters(Arrays.asList(
                        new FormHttpMessageConverter(),
                        new OAuth2AccessTokenResponseHttpMessageConverter()))
                .errorHandler(new OAuth2ErrorResponseErrorHandler())
                .build();
    }
}