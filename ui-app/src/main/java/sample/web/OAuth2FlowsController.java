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

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import org.thymeleaf.util.StringUtils;
import sample.config.ServicesConfig;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

/**
 * @author Joe Grandja
 */
@Controller
@RequestMapping("/oauth2-flows")
public class OAuth2FlowsController {
	private static final String FLOW_TYPE_PARAMETER = "flowType";
	private final WebClient webClient;
	private final ServicesConfig servicesConfig;

	public OAuth2FlowsController(WebClient webClient, ServicesConfig servicesConfig) {
		this.webClient = webClient;
		this.servicesConfig = servicesConfig;
	}

	@GetMapping("/flow-a")
	public String flowA(@RegisteredOAuth2AuthorizedClient("client-a") OAuth2AuthorizedClient clientA,
						OAuth2AuthenticationToken oauth2Authentication,
						HttpServletRequest request,
						Map<String, Object> model) {

		ServiceCallResponse serviceACallResponse = callService(ServicesConfig.SERVICE_A, clientA);

		model.put("flowACall", fromUiApp(oauth2Authentication, request, serviceACallResponse));

		return "index";
	}

	@GetMapping("/flow-ab")
	public String flowAB(@RegisteredOAuth2AuthorizedClient("client-ab") OAuth2AuthorizedClient clientAB,
						OAuth2AuthenticationToken oauth2Authentication,
						HttpServletRequest request,
						Map<String, Object> model) {

		ServiceCallResponse serviceACallResponse = callService(ServicesConfig.SERVICE_A, clientAB);
		ServiceCallResponse serviceBCallResponse = callService(ServicesConfig.SERVICE_B, clientAB);

		model.put("flowABCall", fromUiApp(oauth2Authentication, request, serviceACallResponse, serviceBCallResponse));

		return "index";
	}

	@GetMapping("/flow-abc")
	public String flowABC(@RegisteredOAuth2AuthorizedClient("client-abc") OAuth2AuthorizedClient clientABC,
							OAuth2AuthenticationToken oauth2Authentication,
							HttpServletRequest request,
							Map<String, Object> model) {

		ServiceCallResponse serviceACallResponse = callService(ServicesConfig.SERVICE_A, clientABC);

		String modelAttr = "flowABCCall";
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		String flowType = request.getParameter(FLOW_TYPE_PARAMETER);
		if (!StringUtils.isEmpty(flowType)) {
			params.put(FLOW_TYPE_PARAMETER, Collections.singletonList(flowType));
			modelAttr += "_" + flowType;
		}
		ServiceCallResponse serviceBCallResponse = callService(ServicesConfig.SERVICE_B, clientABC, params);

		model.put(modelAttr, fromUiApp(oauth2Authentication, request, serviceACallResponse, serviceBCallResponse));

		return "index";
	}

	private ServiceCallResponse callService(String serviceId, OAuth2AuthorizedClient authorizedClient) {
		return callService(serviceId, authorizedClient, new LinkedMultiValueMap<>());
	}

	private ServiceCallResponse callService(String serviceId, OAuth2AuthorizedClient authorizedClient, MultiValueMap<String, String> params) {
		ServicesConfig.ServiceConfig serviceConfig = this.servicesConfig.getConfig(serviceId);
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(serviceConfig.getUri());
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

	private ServiceCallResponse fromUiApp(OAuth2AuthenticationToken oauth2Authentication,
										  HttpServletRequest request,
										  ServiceCallResponse... serviceCallResponses) {

		OidcUser oidcUser = (OidcUser) oauth2Authentication.getPrincipal();

		ServiceCallResponse serviceCallResponse = new ServiceCallResponse();
		serviceCallResponse.setServiceName(ServicesConfig.UI_APP);
		serviceCallResponse.setServiceUri(request.getRequestURL().toString());
		serviceCallResponse.setJti("(opaque to client)");
		serviceCallResponse.setSub(oidcUser.getSubject());
		serviceCallResponse.setAud(oidcUser.getAudience());
		serviceCallResponse.setAuthorities(oauth2Authentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
		if (serviceCallResponses != null) {
			serviceCallResponse.setServiceCallResponses(Arrays.asList(serviceCallResponses));
		}

		return serviceCallResponse;
	}
}