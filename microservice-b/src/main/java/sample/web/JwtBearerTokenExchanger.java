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

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.DefaultJwtBearerTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.JwtBearerGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * @author Joe Grandja
 */
@Component
public final class JwtBearerTokenExchanger {
	private final ClientRegistrationRepository clientRegistrationRepository;
	private final OAuth2AuthorizedClientService authorizedClientService;
	private final OAuth2AccessTokenResponseClient<JwtBearerGrantRequest> jwtBearerTokenResponseClient =
			new DefaultJwtBearerTokenResponseClient();
	private final Map<String, Jwt> jwtExchanges = new ConcurrentHashMap<>();
	private final Function<ClientRegistration, JwtDecoder> jwtDecoders = new JwtDecoderFactory();

	public JwtBearerTokenExchanger(ClientRegistrationRepository clientRegistrationRepository,
									OAuth2AuthorizedClientService authorizedClientService) {
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientService = authorizedClientService;
	}

	public @Nullable Jwt exchange(Jwt jwt, String clientRegistrationId) {
		Jwt exchangedJwt = this.jwtExchanges.get(jwt.getId());
		if (exchangedJwt != null) {
			return exchangedJwt;
		}

		ClientRegistration clientRegistration =
				this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
		if (clientRegistration == null) {
			return null;
		}

		OAuth2AuthorizedClient authorizedClient = authorizeJwtBearerClient(jwt, clientRegistration);

		JwtDecoder jwtDecoder = this.jwtDecoders.apply(clientRegistration);
		exchangedJwt = jwtDecoder.decode(authorizedClient.getAccessToken().getTokenValue());
		this.jwtExchanges.put(jwt.getId(), exchangedJwt);

		return exchangedJwt;
	}

	private OAuth2AuthorizedClient authorizeJwtBearerClient(Jwt jwt, ClientRegistration clientRegistration) {
		JwtBearerGrantRequest jwtBearerGrantRequest = new JwtBearerGrantRequest(clientRegistration, jwt);
		OAuth2AccessTokenResponse tokenResponse =
				this.jwtBearerTokenResponseClient.getTokenResponse(jwtBearerGrantRequest);

		Authentication subjectAuthentication = new SubjectAuthentication(jwt.getSubject());
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				clientRegistration, subjectAuthentication.getName(), tokenResponse.getAccessToken());
		this.authorizedClientService.saveAuthorizedClient(authorizedClient, subjectAuthentication);

		return authorizedClient;
	}

	private static class JwtDecoderFactory implements Function<ClientRegistration, JwtDecoder> {
		private static final String MISSING_SIGNATURE_VERIFIER_ERROR_CODE = "missing_signature_verifier";
		private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

		@Override
		public JwtDecoder apply(ClientRegistration clientRegistration) {
			JwtDecoder jwtDecoder = this.jwtDecoders.get(clientRegistration.getRegistrationId());
			if (jwtDecoder == null) {
				if (!StringUtils.hasText(clientRegistration.getProviderDetails().getJwkSetUri())) {
					OAuth2Error oauth2Error = new OAuth2Error(
							MISSING_SIGNATURE_VERIFIER_ERROR_CODE,
							"Failed to find a Signature Verifier for Client Registration: '" +
									clientRegistration.getRegistrationId() +
									"'. Check to ensure you have configured the JwkSet URI.",
							null
					);
					throw new OAuth2AuthorizationException(oauth2Error);
				}
				jwtDecoder = new NimbusJwtDecoderJwkSupport(clientRegistration.getProviderDetails().getJwkSetUri());
				this.jwtDecoders.put(clientRegistration.getRegistrationId(), jwtDecoder);
			}
			return jwtDecoder;
		}
	}

	private static class SubjectAuthentication implements Authentication {
		private final String subject;

		private SubjectAuthentication(String subject) {
			this.subject = subject;
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			throw unsupported();
		}

		@Override
		public Object getPrincipal() {
			throw unsupported();
		}

		@Override
		public Object getCredentials() {
			throw unsupported();
		}

		@Override
		public Object getDetails() {
			throw unsupported();
		}

		@Override
		public boolean isAuthenticated() {
			throw unsupported();
		}

		@Override
		public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
			throw unsupported();
		}

		@Override
		public String getName() {
			return this.subject;
		}

		private UnsupportedOperationException unsupported() {
			return new UnsupportedOperationException("Not Supported");
		}
	}
}