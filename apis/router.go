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

package apis

import (
	"fmt"
	"net/http"
	"path"

	"proxy-manager/apis/management"
	"proxy-manager/apis/middlewares"
	"proxy-manager/apis/proxy"
	"proxy-manager/apis/status_routes"
	"proxy-manager/internal/config"
	auth "proxy-manager/services/authentication"
	proxyservice "proxy-manager/services/proxies"

	"github.com/gorilla/mux"
	glogrus "github.com/mia-platform/glogger/v4/loggers/logrus"
	gmux "github.com/mia-platform/glogger/v4/middleware/mux"
	"github.com/sirupsen/logrus"
)

func SetupRouter(log *logrus.Logger, config *config.ServiceConfig, proxiesCache *proxyservice.ProxyCache, env config.EnvironmentVariables, tokensCache *auth.TokensCache) http.Handler {
	router := mux.NewRouter()

	status_routes.SetupRoutes(router, "proxy-manager", env.ServiceVersion)

	serviceRouter := router
	if env.ServicePrefix != "" && env.ServicePrefix != "/" {
		serviceRouter = router.PathPrefix(fmt.Sprintf("%s/", path.Clean(env.ServicePrefix))).Subrouter()
	}

	SetupMiddlewares(serviceRouter, env, log)

	management.SetupManagementRoutes(serviceRouter, env)
	proxy.SetupRoutes(serviceRouter, config, proxiesCache, env, tokensCache)

	return router
}

func SetupMiddlewares(router *mux.Router, env config.EnvironmentVariables, log *logrus.Logger) {
	middlewareLog := glogrus.GetLogger(logrus.NewEntry(log))
	router.Use(gmux.RequestMiddlewareLogger(middlewareLog, []string{"/-/"}))

	router.Use(middlewares.EnvMiddleware(env))
	router.Use(middlewares.DependenciesMiddleware())

	if env.ServiceConfigUrl != "" {
		router.Use(middlewares.CrudClientRegister[proxyservice.CrudProxy](env.ServiceConfigUrl))
	}
}
