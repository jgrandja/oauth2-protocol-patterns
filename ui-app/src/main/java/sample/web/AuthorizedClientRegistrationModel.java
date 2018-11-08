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

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/**
 * @author Joe Grandja
 */
public class AuthorizedClientRegistrationModel {
	private final ClientRegistration clientRegistration;
	private final OAuth2AuthorizedClient authorizedClient;

	public AuthorizedClientRegistrationModel(ClientRegistration clientRegistration,
												OAuth2AuthorizedClient authorizedClient) {
		this.clientRegistration = clientRegistration;
		this.authorizedClient = authorizedClient;
	}

	public String getClientId() {
		return getClientRegistration().getClientId();
	}

	public String getAuthorizationGrantType() {
		return getClientRegistration().getAuthorizationGrantType().getValue();
	}

	public boolean isAuthorized() {
		return getAuthorizedClient() != null;
	}

	public Set<String> getAuthorizedScopes() {
		return isAuthorized() ?
				new TreeSet<>(getAuthorizedClient().getAccessToken().getScopes()) :
				Collections.emptySet();
	}

	ClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

	OAuth2AuthorizedClient getAuthorizedClient() {
		return this.authorizedClient;
	}
}