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

import java.util.List;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

/**
 * @author Joe Grandja
 * @author Stefan Ganzer
 */
@RestController
@RequestMapping("/service-c")
public class ServiceCController {
	private static final String SERVICE_C = "service-c";

	@GetMapping
	public ServiceCallResponse serviceC(JwtAuthenticationToken jwtAuthentication,
										HttpServletRequest request) {
    ServiceCallResponse serviceCallResponse = new ServiceCallResponse(
        SERVICE_C,
        request.getRequestURL().toString(),
        jwtAuthentication.getToken().getId(),
        jwtAuthentication.getToken().getSubject(),
        jwtAuthentication.getToken().getAudience(),
        jwtAuthentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority).sorted().toList(),
        Map.of(),
        List.of());

		return serviceCallResponse;
	}
}
