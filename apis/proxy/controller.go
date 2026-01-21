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

package proxy

import (
	"proxy-manager/internal/config"
	auth "proxy-manager/services/authentication"
	proxyservice "proxy-manager/services/proxies"

	"github.com/gorilla/mux"
)

func SetupRoutes(router *mux.Router, config *config.ServiceConfig, proxiesCache *proxyservice.ProxyCache, env config.EnvironmentVariables, tokensCache *auth.TokensCache) {
	if env.IsStaticConfiguration() {
		for _, proxy := range config.Proxies {
			s := router.PathPrefix(proxy.BasePath)
			s.HandlerFunc(ProxyHandler(proxy, env, tokensCache))
		}
	}
	if env.IsDynamicConfiguration() {
		s := router.PathPrefix("/")
		s.HandlerFunc(DynamicProxyHandler(proxiesCache, env, tokensCache))
	}
}
