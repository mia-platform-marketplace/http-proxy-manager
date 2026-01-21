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

package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"proxy-manager/internal/config"
	"proxy-manager/services/allowedtargets"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestDependenciesMiddleware(t *testing.T) {
	t.Run("panics if missing envs", func(t *testing.T) {
		router := mux.NewRouter()
		router.Use(DependenciesMiddleware())

		router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			t.Error("handler should not be called")
		})

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		shouldPanicFn := func() {
			router.ServeHTTP(w, req)
		}

		assert.PanicsWithError(t, "no envs registered in context", shouldPanicFn)
	})

	t.Run("panics if invalid AllowedProxyTargetURLs is set", func(t *testing.T) {
		envs := config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				string([]byte{0x7f}),
			},
		}

		router := mux.NewRouter()
		router.Use(EnvMiddleware(envs))
		router.Use(DependenciesMiddleware())

		router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			t.Error("handler should not be called")
		})

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		shouldPanicFn := func() {
			router.ServeHTTP(w, req)
		}

		assert.PanicsWithError(t, "parse \"\\x7f\": net/url: invalid control character in URL", shouldPanicFn)
	})

	t.Run("adds dependencies to context and resolves them correctly", func(t *testing.T) {
		expectedEnv := config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{"http://some-domain.org", "https://apis.some-domain-com"},
		}

		validTargetURL := "https://apis.some-domain-com/some/path"
		notValidTargetURL := "https://not-valid-domain"

		router := mux.NewRouter()
		router.Use(EnvMiddleware(expectedEnv))
		router.Use(DependenciesMiddleware())

		isCalled := false
		router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			isCalled = true

			svc, err := allowedtargets.Resolve(r.Context())
			assert.Nil(t, err)
			assert.NotNil(t, svc)

			assert.Error(t, svc.AssertTargetAllowed(notValidTargetURL), "specified target URL is not allowed")
			assert.Nil(t, svc.AssertTargetAllowed(validTargetURL))
		})

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.True(t, isCalled)
	})
}
