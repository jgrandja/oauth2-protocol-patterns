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
import org.springframework.security.oauth2.core.oidc.OidcScopes;

import java.util.Set;
import java.util.TreeSet;

/**
 * @author Joe Grandja
 */
public class AuthorizedClientModel {
	private final OAuth2AuthorizedClient authorizedClient;

	public AuthorizedClientModel(OAuth2AuthorizedClient authorizedClient) {
		this.authorizedClient = authorizedClient;
	}

	public String getClientId() {
		return getAuthorizedClient().getClientRegistration().getClientId();
	}

	public boolean isOidcClient() {
		return getAuthorizedClient().getAccessToken().getScopes().contains(OidcScopes.OPENID);
	}

	public String getAuthorizationGrantType() {
		return getAuthorizedClient().getClientRegistration().getAuthorizationGrantType().getValue();
	}

	public Set<String> getScopes() {
		return new TreeSet<>(getAuthorizedClient().getAccessToken().getScopes());
	}

	public String getAccessTokenValue() {
		return getAuthorizedClient().getAccessToken().getTokenValue();
	}

	public String getRefreshTokenValue() {
		return getAuthorizedClient().getRefreshToken() != null ?
				getAuthorizedClient().getRefreshToken().getTokenValue() :
				null;
	}

	private OAuth2AuthorizedClient getAuthorizedClient() {
		return this.authorizedClient;
	}
}