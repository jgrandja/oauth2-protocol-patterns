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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import sample.config.ServicesConfig;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.stream.Collectors;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

/**
 * @author Joe Grandja
 */
@RestController
@RequestMapping("/service-b")
public class ServiceBController {
	private static final String SERVICE_B = "service-b";
	private static final String CLIENT_ABC = "client-abc";
	private final WebClient webClient;
	private final ServicesConfig servicesConfig;

	@Autowired
	private JwtBearerTokenExchanger tokenExchanger;

	public ServiceBController(WebClient webClient, ServicesConfig servicesConfig) {
		this.webClient = webClient;
		this.servicesConfig = servicesConfig;
	}

	@GetMapping
	public ServiceCall serviceB(@AuthenticationPrincipal JwtAuthenticationToken jwtAuthentication,
								HttpServletRequest request) {

		return fromServiceB(jwtAuthentication, request);
	}

	@GetMapping(params = {"flowType=token_relay"})
	public ServiceCall serviceB_TokenRelay(@AuthenticationPrincipal JwtAuthenticationToken jwtAuthentication,
											HttpServletRequest request) {

		ServiceCall serviceCCall = callServiceC(jwtAuthentication.getToken());
		return fromServiceB(jwtAuthentication, request, serviceCCall);
	}

	@GetMapping(params = {"flowType=token_exchange"})
	public ServiceCall serviceB_TokenExchange(@AuthenticationPrincipal JwtAuthenticationToken jwtAuthentication,
												HttpServletRequest request) {

		Jwt exchangedJwt = this.tokenExchanger.exchange(jwtAuthentication.getToken(), CLIENT_ABC);
		ServiceCall serviceCCall = callServiceC(exchangedJwt);
		return fromServiceB(jwtAuthentication, request, serviceCCall);
	}

	@GetMapping(params = {"flowType=client_credentials"})
	public ServiceCall serviceB_ClientCredentials(@AuthenticationPrincipal JwtAuthenticationToken jwtAuthentication,
													@RegisteredOAuth2AuthorizedClient("client-c") OAuth2AuthorizedClient clientC,
											  		HttpServletRequest request) {

		ServiceCall serviceCCall = callServiceC(clientC);
		return fromServiceB(jwtAuthentication, request, serviceCCall);
	}

	private ServiceCall callServiceC(Jwt jwt) {
		ServicesConfig.ServiceConfig serviceConfig = this.servicesConfig.getConfig(ServicesConfig.SERVICE_C);
		return this.webClient
				.get()
				.uri(serviceConfig.getUri())
				.headers(headers -> headers.setBearerAuth(jwt.getTokenValue()))
				.retrieve()
				.bodyToMono(ServiceCall.class)
				.block();
	}

	private ServiceCall callServiceC(OAuth2AuthorizedClient authorizedClient) {
		ServicesConfig.ServiceConfig serviceConfig = this.servicesConfig.getConfig(ServicesConfig.SERVICE_C);
		return this.webClient
				.get()
				.uri(serviceConfig.getUri())
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(ServiceCall.class)
				.block();
	}

	private ServiceCall fromServiceB(JwtAuthenticationToken jwtAuthentication,
										HttpServletRequest request,
										ServiceCall... serviceCalls) {

		ServiceCall serviceCall = new ServiceCall();
		serviceCall.setServiceName(SERVICE_B);
		serviceCall.setServiceUri(request.getRequestURL().toString());
		serviceCall.setJti(jwtAuthentication.getToken().getId());
		serviceCall.setSub(jwtAuthentication.getToken().getSubject());
		serviceCall.setAud(jwtAuthentication.getToken().getAudience());
		serviceCall.setAuthorities(jwtAuthentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
		if (serviceCalls != null) {
			serviceCall.setServiceCalls(Arrays.asList(serviceCalls));
		}

		return serviceCall;
	}
}