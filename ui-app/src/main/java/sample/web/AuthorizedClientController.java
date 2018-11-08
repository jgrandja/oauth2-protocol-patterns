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

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
@Controller
@RequestMapping("/authorized-clients")
public class AuthorizedClientController {

	@SuppressWarnings("unchecked")
	@GetMapping
	public String authorizedClients(Map<String, Object> model, @AuthenticationPrincipal OidcUser oidcUser) {
		List<AuthorizedClientRegistrationModel> authorizedClientRegistrations =
				(List<AuthorizedClientRegistrationModel>) model.get("authorizedClientRegistrations");

		List<AuthorizedClientModel> authorizedClients = authorizedClientRegistrations.stream()
				.filter(e -> Objects.nonNull(e.getAuthorizedClient()))
				.map(AuthorizedClientRegistrationModel::getAuthorizedClient)
				.map(AuthorizedClientModel::new)
				.collect(Collectors.toList());
		model.put("authorizedClients", authorizedClients);
		model.put("idTokenValue", oidcUser.getIdToken().getTokenValue());

		return "authorized-clients";
	}
}