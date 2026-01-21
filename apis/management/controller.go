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

package management

import (
	"net/http"

	"proxy-manager/internal/config"

	"github.com/gorilla/mux"
)

func SetupManagementRoutes(router *mux.Router, env config.EnvironmentVariables) {
	if env.IsDynamicConfiguration() && env.ExposeManagementAPIs {
		router.HandleFunc("/-/proxies", GetProxiesHandler).Methods(http.MethodGet)
		router.HandleFunc("/-/proxies", CreateProxyHandler).Methods(http.MethodPost)
		router.HandleFunc("/-/proxies/{id}", UpdateProxyByIdHandler).Methods(http.MethodPatch)
		router.HandleFunc("/-/proxies", UpdateProxyByBasePathHandler).Methods(http.MethodPatch)
		router.HandleFunc("/-/proxies", DeleteProxiesHandler).Methods(http.MethodDelete)
	}
}
