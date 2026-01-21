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
	"net/http"
	"net/http/httputil"

	apihelpers "proxy-manager/apis/helpers"
	"proxy-manager/entities"
	"proxy-manager/internal/config"
	"proxy-manager/internal/pathextractor"
	"proxy-manager/services/allowedtargets"
	auth "proxy-manager/services/authentication"
	"proxy-manager/services/proxies"

	glogrus "github.com/mia-platform/glogger/v4/loggers/logrus"
	"github.com/sirupsen/logrus"
)

func ProxyHandler(proxy *entities.Proxy, env config.EnvironmentVariables, tokensCache *auth.TokensCache) func(http.ResponseWriter, *http.Request) {
	var handler func(http.ResponseWriter, *http.Request)
	switch proxy.Authentication {
	case "oauth2":
		{
			handler = func(w http.ResponseWriter, req *http.Request) {
				logger := glogrus.FromContext(req.Context())
				err := assertAllowedProxyToTarget(req, proxy)
				if err != nil {
					logger.WithError(err).Error("failed to proxy request to a not allowed target URL")
					apihelpers.WriteResponse(w, http.StatusInternalServerError, nil, []byte(err.Error()))
					return
				}

				token, err := tokensCache.GetAccessToken(logger, proxy)
				if err != nil {
					logger.WithError(err).Error("failed retrieving access token")
					apihelpers.WriteResponse(w, http.StatusInternalServerError, nil, []byte(err.Error()))
					return
				}

				if env.AllowProxyOptimizer {
					proxy := httputil.ReverseProxy{
						Director:       ProxyDirector(logger, env, token, proxy),
						ModifyResponse: getResponseModifier(logger, proxy, tokensCache, env),
					}
					proxy.ServeHTTP(w, req)
					return
				}

				status, headers, body, err := ProxyWithRetries(logger, env, req, token, proxy, tokensCache)
				if err != nil {
					apihelpers.WriteResponse(w, http.StatusInternalServerError, nil, []byte(err.Error()))
					return
				}
				apihelpers.WriteResponse(w, status, headers, body)
			}
		}
	default:
		{
			handler = func(w http.ResponseWriter, req *http.Request) {
				logger := glogrus.FromContext(req.Context())
				err := assertAllowedProxyToTarget(req, proxy)
				if err != nil {
					logger.WithError(err).Error("failed to proxy request to a not allowed target URL")
					apihelpers.WriteResponse(w, http.StatusInternalServerError, nil, []byte(err.Error()))
					return
				}

				if env.AllowProxyOptimizer {
					proxy := httputil.ReverseProxy{
						Director:       ProxyDirector(logger, env, "", proxy),
						ModifyResponse: getResponseModifier(logger, proxy, tokensCache, env),
					}
					proxy.ServeHTTP(w, req)
					return
				}

				status, headers, body := makeRequest(logger, env, req, "", proxy)
				apihelpers.WriteResponse(w, status, headers, body)
			}
		}
	}
	return handler
}

func DynamicProxyHandler(
	proxiesCache *proxies.ProxyCache,
	env config.EnvironmentVariables,
	tokensCache *auth.TokensCache,
) func(http.ResponseWriter, *http.Request) {
	var basePathExtractorGraphRootNode *pathextractor.Node
	if len(env.BasePathExtractorPrefixes) > 0 {
		basePathExtractorGraphRootNode = pathextractor.CreateBasePathExtractorGraph(env.BasePathExtractorPrefixes)
	}

	return func(w http.ResponseWriter, req *http.Request) {
		logger := glogrus.FromContext(req.Context())

		basePath := extractBasePath(req.URL.Path, basePathExtractorGraphRootNode)

		proxy, err := getFromCacheOrFetchProxy(logger, basePath, proxiesCache, env)
		if err != nil {
			logger.WithError(err).Error("failed to fetch and update proxy cache")
			apihelpers.WriteResponse(w, http.StatusInternalServerError, nil, []byte(err.Error()))
			return
		}

		ProxyHandler(proxy, env, tokensCache)(w, req)
	}
}

func getFromCacheOrFetchProxy(logger *logrus.Entry, basePath string, proxiesCache *proxies.ProxyCache, env config.EnvironmentVariables) (*entities.Proxy, error) {
	if proxiesCache == nil {
		return proxies.FetchProxy(env.ServiceConfigUrl, basePath)
	}

	// FIXME: this code causes race conditions, we must fix it
	proxyCache, isPresent := (*proxiesCache)[basePath]
	if !isPresent || proxyCache.IsExpired() {
		logger.Trace("fetching proxy configuration from CRUD")
		if err := proxies.FetchAndUpdateProxyCache(env.ServiceConfigUrl, basePath, proxiesCache, env.ProxyCacheTTL); err != nil {
			return nil, err
		}
		proxyCache = (*proxiesCache)[basePath]
	}
	return &proxyCache.Proxy, nil
}

func assertAllowedProxyToTarget(req *http.Request, proxy *entities.Proxy) error {
	service, err := allowedtargets.Resolve(req.Context())
	if err != nil {
		return err
	}

	return service.AssertTargetAllowed(proxy.TargetBaseUrl)
}
