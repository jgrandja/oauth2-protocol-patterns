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

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * @author Joe Grandja
 */
public class ServiceCallResponse {
	private String serviceName;
	private String serviceUri;
	private String jti;
	private String sub;
	private List<String> aud = Collections.emptyList();
	private List<String> authorities = Collections.emptyList();
	private Map<String, Object> additionalInfo = Collections.emptyMap();
	private List<ServiceCallResponse> serviceCallResponses = Collections.emptyList();

	public String getServiceName() {
		return this.serviceName;
	}

	public void setServiceName(String serviceName) {
		this.serviceName = serviceName;
	}

	public String getServiceUri() {
		return this.serviceUri;
	}

	public void setServiceUri(String serviceUri) {
		this.serviceUri = serviceUri;
	}

	public String getJti() {
		return this.jti;
	}

	public void setJti(String jti) {
		this.jti = jti;
	}

	public String getSub() {
		return this.sub;
	}

	public void setSub(String sub) {
		this.sub = sub;
	}

	public List<String> getAud() {
		return this.aud;
	}

	public void setAud(List<String> aud) {
		this.aud = aud;
	}

	public List<String> getAuthorities() {
		return this.authorities;
	}

	public void setAuthorities(List<String> authorities) {
		this.authorities = authorities;
	}

	public Map<String, Object> getAdditionalInfo() {
		return this.additionalInfo;
	}

	public void setAdditionalInfo(Map<String, Object> additionalInfo) {
		this.additionalInfo = additionalInfo;
	}

	public List<ServiceCallResponse> getServiceCallResponses() {
		return this.serviceCallResponses;
	}

	public void setServiceCallResponses(List<ServiceCallResponse> serviceCallResponses) {
		this.serviceCallResponses = serviceCallResponses;
	}
}