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

import java.util.List;
import java.util.Map;

/**
 * @author Joe Grandja
 * @author Stefan Ganzer
 */
public record ServiceCallResponse(
    String serviceName,
    String serviceUri,
    String jti,
    String sub,
    List<String> aud,
    List<String> authorities,
    Map<String, Object> additionalInfo,
    List<ServiceCallResponse> serviceCallResponses) {}
