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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	apihelpers "proxy-manager/apis/helpers"
	"proxy-manager/internal/config"
	proxyservice "proxy-manager/services/proxies"
	"testing"

	"github.com/mia-platform/go-crud-service-client"
	"github.com/mia-platform/go-crud-service-client/testhelper/mock"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

func TestCreateProxyHandler(t *testing.T) {
	t.Run("400 on body parse failure", func(t *testing.T) {
		req := GetMockedRequest(t, http.MethodPost, "/-/proxies", nil, nil, config.EnvironmentVariables{})
		w := httptest.NewRecorder()

		CreateProxyHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, 400, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var foundError apihelpers.RequestError
		json.Unmarshal(responseBody, &foundError)

		expectedMessage := "failed request body deserialization"
		assert.Equal(t, foundError.Message, expectedMessage, "Wrong response body.")
	})

	t.Run("400 on proxy validation failure", func(t *testing.T) {
		invalidProxy := proxyservice.CrudProxy{BasePath: "/base-path"}

		req := GetMockedRequest(
			t,
			http.MethodPost,
			"/-/proxies",
			CreateRequestBody(t, invalidProxy),
			nil,
			config.EnvironmentVariables{},
		)
		w := httptest.NewRecorder()

		CreateProxyHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, 400, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var foundError apihelpers.RequestError
		json.Unmarshal(responseBody, &foundError)

		expectedMessage := "the provided proxy is invalid"
		assert.Equal(t, foundError.Message, expectedMessage, "Wrong response body.")
	})

	t.Run("500 on proxy creation failure on crud", func(t *testing.T) {
		proxyToCreate := proxyservice.CrudProxy{
			BasePath:      "/base-path",
			TargetBaseUrl: "https://example.com",
		}
		crudClient := &mock.CRUD[proxyservice.CrudProxy]{
			CreateError: fmt.Errorf("item creation failed"),
		}

		req := GetMockedRequest(
			t,
			http.MethodPost,
			"/-/proxies",
			CreateRequestBody(t, proxyToCreate),
			crudClient,
			config.EnvironmentVariables{},
		)
		w := httptest.NewRecorder()
		CreateProxyHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, 500, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var foundError apihelpers.RequestError
		json.Unmarshal(responseBody, &foundError)

		expectedMessage := "failed to create new proxy"
		assert.Equal(t, foundError.Message, expectedMessage, "Wrong response body.")
	})

	t.Run("200 on successful proxy creation", func(t *testing.T) {
		proxyToCreate := proxyservice.CrudProxy{
			BasePath:      "/base-path",
			TargetBaseUrl: "https://example.com",
		}
		expectedProxyId := "proxy_oid"

		crudClient := &mock.CRUD[proxyservice.CrudProxy]{
			CreateResult: expectedProxyId,
			CreateAssertionFunc: func(_ context.Context, resource proxyservice.CrudProxy, options crud.Options) {
				require.Equal(t, proxyToCreate, resource)
			},
		}

		req := GetMockedRequest(
			t,
			http.MethodPost,
			"/-/proxies",
			CreateRequestBody(t, proxyToCreate),
			crudClient,
			config.EnvironmentVariables{},
		)
		w := httptest.NewRecorder()
		CreateProxyHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, 200, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var response CreateProxyResponse
		json.Unmarshal(responseBody, &response)

		assert.Equal(t, response.ProxyId, expectedProxyId, "Wrong response body.")
	})
}
