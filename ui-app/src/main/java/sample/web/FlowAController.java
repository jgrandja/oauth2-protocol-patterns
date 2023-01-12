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
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.reactive.function.client.WebClient;
import sample.config.ServicesConfig;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * @author Joe Grandja
 */
@Controller
@RequestMapping("/flow-a")
public class FlowAController extends AbstractFlowController {

	public FlowAController(WebClient webClient, ServicesConfig servicesConfig) {
		super(webClient, servicesConfig);
	}

	@GetMapping
	public String flowA(@RegisteredOAuth2AuthorizedClient("client-a") OAuth2AuthorizedClient clientA,
						OAuth2AuthenticationToken oauth2Authentication,
						HttpServletRequest request,
						Map<String, Object> model) {

		ServiceCallResponse serviceACallResponse = callService(ServicesConfig.SERVICE_A, clientA);

		model.put("flowACall", fromUiApp(oauth2Authentication, request, serviceACallResponse));
		model.put("flowActive", true);

		return "index";
	}
}
