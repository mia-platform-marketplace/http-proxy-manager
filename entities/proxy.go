/**
 * Copyright 2026 Mia srl
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package entities

type AdditionalHeader struct {
	Name  string `json:"name" koanf:"name"`
	Value string `json:"value" koanf:"value"`
}

type Proxy struct {
	BasePath                 string             `json:"basePath" koanf:"basePath"`
	TargetBaseUrl            string             `json:"targetBaseUrl" koanf:"targetBaseUrl"`
	Authentication           string             `json:"authentication,omitempty" koanf:"authentication"`
	Username                 string             `json:"username,omitempty" koanf:"username"`
	Password                 string             `json:"password,omitempty" koanf:"password"`
	ClientId                 string             `json:"clientId,omitempty" koanf:"clientId"`
	ClientSecret             string             `json:"clientSecret,omitempty" koanf:"clientSecret"`
	TokenIssuerUrl           string             `json:"tokenIssuerUrl,omitempty" koanf:"tokenIssuerUrl"`
	TokenIssuerValidationUrl string             `json:"tokenIssuerValidationUrl,omitempty" koanf:"tokenIssuerValidationUrl"`
	GrantType                string             `json:"grantType,omitempty" koanf:"grantType"`
	AuthType                 string             `json:"authType,omitempty" koanf:"authType"`
	AdditionalAuthFields     map[string]string  `json:"additionalAuthFields,omitempty" koanf:"additionalAuthFields"`
	HeadersToProxy           []string           `json:"headersToProxy,omitempty" koanf:"headersToProxy"`
	AdditionalHeaders        []AdditionalHeader `json:"additionalHeaders,omitempty" koanf:"additionalHeaders"`
}
