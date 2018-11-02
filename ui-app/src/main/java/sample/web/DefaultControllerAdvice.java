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
import org.springframework.core.ResolvableType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * @author Joe Grandja
 */
@ControllerAdvice
public class DefaultControllerAdvice {

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@Autowired
	private OAuth2AuthorizedClientService authorizedClientService;

	@ModelAttribute("currentUser")
	User currentUser(@AuthenticationPrincipal OidcUser oidcUser) {
		User currentUser = new User();
		if (oidcUser != null) {
			currentUser.setUserId(oidcUser.getSubject());
			currentUser.setFirstName(oidcUser.getGivenName());
			currentUser.setLastName(oidcUser.getFamilyName());
			currentUser.setEmail(oidcUser.getEmail());
		}
		return currentUser;
	}

	@ModelAttribute("idTokenClaims")
	Map<String, Object> idTokenClaims(@AuthenticationPrincipal OidcUser oidcUser) {
		return oidcUser != null ? oidcUser.getIdToken().getClaims() : Collections.emptyMap();
	}

	@ModelAttribute("authorizedClientRegistrations")
	List<AuthorizedClientRegistration> authorizedClientRegistrations(OAuth2AuthenticationToken oauth2Authentication) {
		List<AuthorizedClientRegistration> authorizedClientRegistrations = new ArrayList<>();
		getClientRegistrations().forEach(registration -> {
			OAuth2AuthorizedClient authorizedClient = this.authorizedClientService.loadAuthorizedClient(
					registration.getRegistrationId(), oauth2Authentication.getName());
			authorizedClientRegistrations.add(
					new AuthorizedClientRegistration(registration, authorizedClient));

		});
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

	static class AuthorizedClientRegistration {
		private ClientRegistration clientRegistration;
		private OAuth2AuthorizedClient authorizedClient;

		AuthorizedClientRegistration(ClientRegistration clientRegistration,
										OAuth2AuthorizedClient authorizedClient) {
			this.clientRegistration = clientRegistration;
			this.authorizedClient = authorizedClient;
		}

		public ClientRegistration getClientRegistration() {
			return this.clientRegistration;
		}

		public OAuth2AuthorizedClient getAuthorizedClient() {
			return this.authorizedClient;
		}

		public boolean isAuthorized() {
			return getAuthorizedClient() != null;
		}

		public Set<String> getAuthorizedScopes() {
			return isAuthorized() ? getAuthorizedClient().getAccessToken().getScopes() : Collections.emptySet();
		}
	}
}