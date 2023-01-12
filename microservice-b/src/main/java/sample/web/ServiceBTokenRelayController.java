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

import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import sample.config.ServicesConfig;

import jakarta.servlet.http.HttpServletRequest;

/**
 * @author Joe Grandja
 */
@RestController
@RequestMapping(path = "/service-b", params = {"flowType=token_relay"})
public class ServiceBTokenRelayController extends AbstractFlowController {

	public ServiceBTokenRelayController(WebClient webClient, ServicesConfig servicesConfig) {
		super(webClient, servicesConfig);
	}

	@GetMapping
	public ServiceCallResponse serviceB_TokenRelay(JwtAuthenticationToken jwtAuthentication,
													HttpServletRequest request) {

		ServiceCallResponse serviceCCallResponse = callServiceC(jwtAuthentication.getToken());
		return fromServiceB(jwtAuthentication, request, serviceCCallResponse);
	}
}
