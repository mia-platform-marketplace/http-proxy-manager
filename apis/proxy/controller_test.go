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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"proxy-manager/entities"
	"proxy-manager/internal/config"
	auth "proxy-manager/services/authentication"
	proxyservice "proxy-manager/services/proxies"

	"github.com/gorilla/mux"
	"gopkg.in/h2non/gock.v1"
	"gotest.tools/assert"
)

func TestSetupRoutes(t *testing.T) {
	t.Run("sets up proxy handler with static configuration", func(t *testing.T) {
		router := mux.NewRouter()
		proxiesCache := make(proxyservice.ProxyCache)
		tokensCache := auth.NewTokensCache(30)

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("proxied response"))
		}))

		defer testServer.Close()

		env := config.EnvironmentVariables{ServiceConfigPath: "config-path", ServiceConfigFileName: "config-file-name"}
		config := &config.ServiceConfig{
			Proxies: []*entities.Proxy{
				{BasePath: "/test-service", TargetBaseUrl: testServer.URL},
			},
		}

		SetupRoutes(router, config, &proxiesCache, env, tokensCache)

		req := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "/test-service/path", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "proxied response", w.Body.String())
	})

	t.Run("attempts to call crud with dynamic configuration", func(t *testing.T) {
		t.Run("with cache", func(t *testing.T) {
			router := mux.NewRouter()
			proxiesCache := make(proxyservice.ProxyCache)
			tokensCache := auth.NewTokensCache(30)

			env := config.EnvironmentVariables{ServiceConfigUrl: "http://example.com/config"}

			SetupRoutes(router, nil, &proxiesCache, env, tokensCache)

			req := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// tries to contact the proxies collection
			assert.Equal(t, http.StatusInternalServerError, w.Code)
			assert.Equal(t, "CRUD replied with status code 404", w.Body.String())
		})

		t.Run("without cache", func(t *testing.T) {
			router := mux.NewRouter()
			tokensCache := auth.NewTokensCache(30)

			env := config.EnvironmentVariables{ServiceConfigUrl: "http://example.com/config"}

			SetupRoutes(router, nil, nil, env, tokensCache)

			req := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// tries to contact the proxies collection
			assert.Equal(t, http.StatusInternalServerError, w.Code)
			assert.Equal(t, "CRUD replied with status code 404", w.Body.String())
		})
	})

	t.Run("caching strategy", func(t *testing.T) {
		t.Run("does not invoke crud by re-use cached data if a cache is provided", func(t *testing.T) {
			router := mux.NewRouter()
			proxiesCache := make(proxyservice.ProxyCache)
			tokensCache := auth.NewTokensCache(30)

			env := config.EnvironmentVariables{ServiceConfigUrl: "http://example.com/config", ProxyCacheTTL: 10000}

			expectedProxyResponse, _ := json.Marshal([]entities.Proxy{
				{
					BasePath:      "/base-path-1",
					TargetBaseUrl: "http://proxy-target.com/apis",
				},
			})

			crud := gock.New("http://example.com").
				Get("/config").
				Times(1).
				AddMatcher(getGockBasePathMatcherFromBasePathParam("/base-path-1")).
				Reply(200).
				JSON(expectedProxyResponse)

			proxy1 := gock.New("http://proxy-target.com").
				Get("/apis/my-api").
				Times(1).
				Reply(200)
			proxy2 := gock.New("http://proxy-target.com").
				Get("/apis/my-api-2").
				Times(1).
				Reply(200)
			defer gock.OffAll()

			SetupRoutes(router, nil, &proxiesCache, env, tokensCache)

			req := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "/base-path-1/my-api", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)

			req2 := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "/base-path-1/my-api-2", nil)
			w2 := httptest.NewRecorder()
			router.ServeHTTP(w2, req2)
			assert.Equal(t, http.StatusOK, w2.Code)

			assert.Assert(t, crud.Done())
			assert.Assert(t, proxy1.Done())
			assert.Assert(t, proxy2.Done())
		})

		t.Run("invokes crud multiple times if a cache is not provided", func(t *testing.T) {
			router := mux.NewRouter()
			tokensCache := auth.NewTokensCache(30)

			env := config.EnvironmentVariables{ServiceConfigUrl: "http://example.com/config", ProxyCacheTTL: 10000}

			expectedProxyResponse, _ := json.Marshal([]entities.Proxy{
				{
					BasePath:      "/base-path-1",
					TargetBaseUrl: "http://proxy-target.com/apis",
				},
			})

			crud := gock.New("http://example.com").
				Get("/config").
				Times(2).
				AddMatcher(getGockBasePathMatcherFromBasePathParam("/base-path-1")).
				Reply(200).
				JSON(expectedProxyResponse)

			proxy1 := gock.New("http://proxy-target.com").
				Get("/apis/my-api").
				Times(1).
				Reply(200)
			proxy2 := gock.New("http://proxy-target.com").
				Get("/apis/my-api-2").
				Times(1).
				Reply(200)
			defer gock.OffAll()

			SetupRoutes(router, nil, nil, env, tokensCache)

			req := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "/base-path-1/my-api", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)

			req2 := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "/base-path-1/my-api-2", nil)
			w2 := httptest.NewRecorder()
			router.ServeHTTP(w2, req2)
			assert.Equal(t, http.StatusOK, w2.Code)

			assert.Assert(t, crud.Done())
			assert.Assert(t, proxy1.Done())
			assert.Assert(t, proxy2.Done())
		})
	})
}

func getGockBasePathMatcherFromBasePathParam(basePath string) gock.MatchFunc {
	proxyMatcher := func(req *http.Request, greq *gock.Request) (bool, error) {
		rawQuery := req.URL.Query().Get("basePath")
		if rawQuery != basePath {
			return false, fmt.Errorf("basePath in param '%s' not matching expected basePath: '%s'", rawQuery, basePath)
		}

		return true, nil
	}

	return proxyMatcher
}
