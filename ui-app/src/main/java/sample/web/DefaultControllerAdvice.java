/*
 * Copyright 2002-2019 the original author or authors.
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
import org.springframework.core.ResolvableType;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.servlet.ModelAndView;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * @author Joe Grandja
 */
@ControllerAdvice
public class DefaultControllerAdvice {
	private ClientRegistrationRepository clientRegistrationRepository;
	private OAuth2AuthorizedClientService authorizedClientService;

	@Autowired(required = false)
	void setClientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Autowired(required = false)
	void setAuthorizedClientService(OAuth2AuthorizedClientService authorizedClientService) {
		this.authorizedClientService = authorizedClientService;
	}

	@ModelAttribute("currentUser")
	UserModel currentUser(OAuth2AuthenticationToken oauth2Authentication) {
		UserModel currentUser = new UserModel();
		if (oauth2Authentication != null) {
			OidcUser oidcUser = (OidcUser) oauth2Authentication.getPrincipal();
			currentUser.setUserId(oidcUser.getSubject());
			currentUser.setFirstName(oidcUser.getGivenName());
			currentUser.setLastName(oidcUser.getFamilyName());
			currentUser.setEmail(oidcUser.getEmail());
		}
		return currentUser;
	}

	@ModelAttribute("idTokenClaims")
	Map<String, Object> idTokenClaims(OAuth2AuthenticationToken oauth2Authentication) {
		if (oauth2Authentication == null) {
			return Collections.emptyMap();
		}
		OidcUser oidcUser = (OidcUser) oauth2Authentication.getPrincipal();
		final List<String> claimNames = Arrays.asList("iss", "sub", "aud", "azp", "given_name", "family_name", "email");
		return oidcUser.getClaims().entrySet().stream()
				.filter(e -> claimNames.contains(e.getKey()))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
	}

	@ModelAttribute("authorizedClientRegistrations")
	List<AuthorizedClientRegistrationModel> authorizedClientRegistrations(OAuth2AuthenticationToken oauth2Authentication) {
		if (this.clientRegistrationRepository == null) {
			return Collections.emptyList();
		}
		List<AuthorizedClientRegistrationModel> authorizedClientRegistrations = new ArrayList<>();
		getClientRegistrations().forEach(registration -> {
			OAuth2AuthorizedClient authorizedClient = null;
			if (this.authorizedClientService != null) {
				authorizedClient = this.authorizedClientService.loadAuthorizedClient(
						registration.getRegistrationId(), oauth2Authentication.getName());
			}
			authorizedClientRegistrations.add(
					new AuthorizedClientRegistrationModel(registration, authorizedClient));

		});
		authorizedClientRegistrations.sort(Comparator.comparing(AuthorizedClientRegistrationModel::getClientId));
		return authorizedClientRegistrations;
	}

	private List<ClientRegistration> getClientRegistrations() {
		ResolvableType type = ResolvableType.forInstance(this.clientRegistrationRepository).as(Iterable.class);
		if (type != ResolvableType.NONE && ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
			return StreamSupport.stream(((Iterable<ClientRegistration>) clientRegistrationRepository).spliterator(), false)
					.collect(Collectors.toList());
		}
		return Collections.emptyList();
	}

	@ExceptionHandler(WebClientResponseException.class)
	ModelAndView handleException(WebClientResponseException ex) {
		return errorView("An error occurred on the WebClient response -> [Status: " +
				ex.getStatusCode() + "] " + ex.getStatusText());
	}

	private ModelAndView errorView(String errorMessage) {
		Map<String, Object> model = new HashMap<>();
		model.put("errorMessage", errorMessage);
		return new ModelAndView("error", model);
	}
}