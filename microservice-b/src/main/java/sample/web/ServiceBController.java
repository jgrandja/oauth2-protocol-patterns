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
	public ServiceCallResponse serviceB(@AuthenticationPrincipal JwtAuthenticationToken jwtAuthentication,
										HttpServletRequest request) {

		return fromServiceB(jwtAuthentication, request);
	}

	@GetMapping(params = {"flowType=token_relay"})
	public ServiceCallResponse serviceB_TokenRelay(@AuthenticationPrincipal JwtAuthenticationToken jwtAuthentication,
													HttpServletRequest request) {

		ServiceCallResponse serviceCCallResponse = callServiceC(jwtAuthentication.getToken());
		return fromServiceB(jwtAuthentication, request, serviceCCallResponse);
	}

	@GetMapping(params = {"flowType=token_exchange"})
	public ServiceCallResponse serviceB_TokenExchange(@AuthenticationPrincipal JwtAuthenticationToken jwtAuthentication,
														HttpServletRequest request) {

		Jwt exchangedJwt = this.tokenExchanger.exchange(jwtAuthentication.getToken(), CLIENT_ABC);
		ServiceCallResponse serviceCCallResponse = callServiceC(exchangedJwt);
		return fromServiceB(jwtAuthentication, request, serviceCCallResponse);
	}

	@GetMapping(params = {"flowType=client_credentials"})
	public ServiceCallResponse serviceB_ClientCredentials(@AuthenticationPrincipal JwtAuthenticationToken jwtAuthentication,
															@RegisteredOAuth2AuthorizedClient("client-c") OAuth2AuthorizedClient clientC,
															HttpServletRequest request) {

		ServiceCallResponse serviceCCallResponse = callServiceC(clientC);
		return fromServiceB(jwtAuthentication, request, serviceCCallResponse);
	}

	private ServiceCallResponse callServiceC(Jwt jwt) {
		ServicesConfig.ServiceConfig serviceConfig = this.servicesConfig.getConfig(ServicesConfig.SERVICE_C);
		return this.webClient
				.get()
				.uri(serviceConfig.getUri())
				.headers(headers -> headers.setBearerAuth(jwt.getTokenValue()))
				.retrieve()
				.bodyToMono(ServiceCallResponse.class)
				.block();
	}

	private ServiceCallResponse callServiceC(OAuth2AuthorizedClient authorizedClient) {
		ServicesConfig.ServiceConfig serviceConfig = this.servicesConfig.getConfig(ServicesConfig.SERVICE_C);
		return this.webClient
				.get()
				.uri(serviceConfig.getUri())
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(ServiceCallResponse.class)
				.block();
	}

	private ServiceCallResponse fromServiceB(JwtAuthenticationToken jwtAuthentication,
											 HttpServletRequest request,
											 ServiceCallResponse... serviceCallResponses) {

		ServiceCallResponse serviceCallResponse = new ServiceCallResponse();
		serviceCallResponse.setServiceName(SERVICE_B);
		serviceCallResponse.setServiceUri(request.getRequestURL().toString());
		serviceCallResponse.setJti(jwtAuthentication.getToken().getId());
		serviceCallResponse.setSub(jwtAuthentication.getToken().getSubject());
		serviceCallResponse.setAud(jwtAuthentication.getToken().getAudience());
		serviceCallResponse.setAuthorities(jwtAuthentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
		if (serviceCallResponses != null) {
			serviceCallResponse.setServiceCallResponses(Arrays.asList(serviceCallResponses));
		}

		return serviceCallResponse;
	}
}