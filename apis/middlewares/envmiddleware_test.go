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

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestEnvMiddleware(t *testing.T) {
	t.Run("adds envs to context and retrieves them correctly", func(t *testing.T) {
		expectedEnv := config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{"http://some-domain.org", "https://apis.some-domain-com"},
		}

		router := mux.NewRouter()
		router.Use(EnvMiddleware(expectedEnv))

		isCalled := false
		router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			isCalled = true

			env, err := ResolveEnvs(r.Context())
			assert.Nil(t, err)

			assert.NotNil(t, env)
			assert.Equal(t, expectedEnv, env)
		})

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.True(t, isCalled)
	})
}
