/*
 * Copyright 2002-2018 the original author or authors.
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
package sample.web;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import sample.config.ServicesConfig;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;

/**
 * @author Joe Grandja
 * @author Stefan Ganzer
 */
abstract class AbstractFlowController {
	private static final String SERVICE_B = "service-b";
	private final WebClient webClient;
	private final ServicesConfig servicesConfig;

	protected AbstractFlowController(WebClient webClient, ServicesConfig servicesConfig) {
		this.webClient = webClient;
		this.servicesConfig = servicesConfig;
	}

	protected ServiceCallResponse callServiceC(Jwt jwt) {
		ServicesConfig.ServiceConfig serviceConfig =
				this.servicesConfig.getConfig(ServicesConfig.SERVICE_C);

		return this.webClient
				.get()
				.uri(serviceConfig.uri())
				.headers(headers -> headers.setBearerAuth(jwt.getTokenValue()))
				.retrieve()
        		.onStatus(HttpStatusCode::is3xxRedirection, ClientResponse::createException)
				.bodyToMono(ServiceCallResponse.class)
				.block();
	}

	protected ServiceCallResponse callServiceC(String clientRegistrationId) {
		ServicesConfig.ServiceConfig serviceConfig =
				this.servicesConfig.getConfig(ServicesConfig.SERVICE_C);

		return this.webClient
				.get()
				.uri(serviceConfig.uri())
				.attributes(clientRegistrationId(clientRegistrationId))
				.retrieve()
        		.onStatus(HttpStatusCode::is3xxRedirection, ClientResponse::createException)
				.bodyToMono(ServiceCallResponse.class)
				.block();
	}

	protected ServiceCallResponse fromServiceB(JwtAuthenticationToken jwtAuthentication,
												HttpServletRequest request,
												ServiceCallResponse... serviceCallResponses) {

    ServiceCallResponse serviceCallResponse = new ServiceCallResponse(
        SERVICE_B,
        request.getRequestURL().toString(),
        jwtAuthentication.getToken().getId(),
        jwtAuthentication.getToken().getSubject(),
        jwtAuthentication.getToken().getAudience(),
        jwtAuthentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority).sorted().toList(),
        Map.of(),
        Optional.ofNullable(serviceCallResponses).map(Arrays::asList).orElse(List.of()));

		return serviceCallResponse;
	}
}