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
package sample.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;

/**
 * @author Joe Grandja
 */
@ConfigurationProperties("oauth2.resource")
public class ServicesConfig {
	public static final String SERVICE_C = "service-c";
	private Map<String, ServiceConfig> services;

	public Map<String, ServiceConfig> getServices() {
		return this.services;
	}

	public void setServices(Map<String, ServiceConfig> services) {
		this.services = services;
	}

	public ServiceConfig getConfig(String serviceId) {
		return this.getServices().entrySet().stream()
				.filter(e -> e.getKey().equalsIgnoreCase(serviceId))
				.findFirst()
				.map(Map.Entry::getValue)
				.orElse(null);
	}

	public static class ServiceConfig {
		private String uri;

		public String getUri() {
			return this.uri;
		}

		public void setUri(String uri) {
			this.uri = uri;
		}
	}
}