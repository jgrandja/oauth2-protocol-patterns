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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.Optional;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.SessionAttribute;

import java.util.Map;

/**
 * @author Joe Grandja
 */
@Controller
public class DefaultController {

	@GetMapping("/")
	public String index() {
		return "index";
	}

	@GetMapping(path = "/login", params = "error")
	public String loginError(@SessionAttribute(WebAttributes.AUTHENTICATION_EXCEPTION) AuthenticationException authEx,
												Map<String, Object> model) {
		String errorMessage = authEx != null ? authEx.getMessage() : "[unknown error]";
		model.put("errorMessage", errorMessage);
		return "error";
	}

	@GetMapping("/session-state")
	public String sessionState(Map<String, Object> model, HttpServletRequest request) {
    var sessionId = Optional.ofNullable(request.getSession(false))
        .map(HttpSession::getId)
        .orElse("[no session]");
    model.put("sessionId", sessionId);
		return "session-state";
	}
}
