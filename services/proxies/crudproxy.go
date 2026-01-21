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

package proxies

import "proxy-manager/entities"

const (
	AuthenticationModeNone   = "none"
	AuthenticationModeOauth2 = "oauth2"

	GrantTypePassword          = "password"
	GrantTypeClientCredentials = "client_credentials"

	ClientCredentialsAuthTypeBasic = "client_secret_basic"
)

type CrudProxy struct {
	BasePath                 string                      `json:"basePath"`
	TargetBaseUrl            string                      `json:"targetBaseUrl"`
	Authentication           *string                     `json:"authentication,omitempty"`
	Username                 *string                     `json:"username,omitempty"`
	Password                 *string                     `json:"password,omitempty"`
	ClientId                 *string                     `json:"clientId,omitempty"`
	ClientSecret             *string                     `json:"clientSecret,omitempty"`
	TokenIssuerUrl           *string                     `json:"tokenIssuerUrl,omitempty"`
	TokenIssuerValidationUrl *string                     `json:"tokenIssuerValidationUrl,omitempty"`
	GrantType                *string                     `json:"grantType,omitempty"`
	AuthType                 *string                     `json:"authType,omitempty"`
	AdditionalAuthFields     map[string]string           `json:"additionalAuthFields,omitempty"`
	HeadersToProxy           []string                    `json:"headersToProxy,omitempty"`
	AdditionalHeaders        []entities.AdditionalHeader `json:"additionalHeaders,omitempty"`
}
