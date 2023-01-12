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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import sample.config.ServicesConfig;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Arrays;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

/**
 * @author Joe Grandja
 */
abstract class AbstractFlowController {
	protected static final String FLOW_TYPE_PARAMETER = "flowType";
	private final WebClient webClient;
	private final ServicesConfig servicesConfig;

	protected AbstractFlowController(WebClient webClient, ServicesConfig servicesConfig) {
		this.webClient = webClient;
		this.servicesConfig = servicesConfig;
	}

	protected ServiceCallResponse callService(String serviceId,
												OAuth2AuthorizedClient authorizedClient) {

		return callService(serviceId, authorizedClient, new LinkedMultiValueMap<>());
	}

	protected ServiceCallResponse callService(String serviceId,
												OAuth2AuthorizedClient authorizedClient,
												MultiValueMap<String, String> params) {

		ServicesConfig.ServiceConfig serviceConfig = this.servicesConfig.getConfig(serviceId);
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(serviceConfig.uri());
		if (!params.isEmpty()) {
			uriBuilder.queryParams(params);
		}
		URI uri = uriBuilder.build().toUri();

		return this.webClient
				.get()
				.uri(uri)
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(ServiceCallResponse.class)
				.block();
	}

	protected ServiceCallResponse fromUiApp(OAuth2AuthenticationToken oauth2Authentication,
											HttpServletRequest request,
											ServiceCallResponse... serviceCallResponses) {

		OidcUser oidcUser = (OidcUser) oauth2Authentication.getPrincipal();

		ServiceCallResponse serviceCallResponse = new ServiceCallResponse(
        ServicesConfig.UI_APP,
        request.getRequestURL().toString(),
        "opaque to client",
        oidcUser.getSubject(),
        oidcUser.getAudience(),
        oauth2Authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList(),
        Map.of(),
        Optional.ofNullable(serviceCallResponses).map(Arrays::asList).orElse(List.of())
    );

		return serviceCallResponse;
	}
}
