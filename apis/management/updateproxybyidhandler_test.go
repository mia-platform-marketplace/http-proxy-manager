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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	apihelpers "proxy-manager/apis/helpers"
	"proxy-manager/internal/config"
	proxyservice "proxy-manager/services/proxies"

	"github.com/gorilla/mux"
	"github.com/mia-platform/go-crud-service-client"
	"github.com/mia-platform/go-crud-service-client/testhelper/mock"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

func TestUpdateProxyByIdHandler(t *testing.T) {
	t.Run("400 on missing proxyId path param", func(t *testing.T) {
		proxy := proxyservice.CrudProxy{
			BasePath:      "/base-path",
			TargetBaseUrl: "https://example.com",
		}
		req := GetMockedRequest(t, http.MethodPatch, "/-/proxies", CreateRequestBody(t, proxy), nil, config.EnvironmentVariables{})

		w := httptest.NewRecorder()

		UpdateProxyByIdHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, 400, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var foundError apihelpers.RequestError
		json.Unmarshal(responseBody, &foundError)

		expectedMessage := "missing id path parameter"
		assert.Equal(t, foundError.Message, expectedMessage, "Wrong response body.")
	})

	t.Run("400 on body parse failure", func(t *testing.T) {
		req := GetMockedRequest(t, http.MethodPatch, "/-/proxies/proxy-id", nil, nil, config.EnvironmentVariables{})
		vars := map[string]string{
			"id": "proxy-id",
		}
		req = mux.SetURLVars(req, vars)

		w := httptest.NewRecorder()

		UpdateProxyByIdHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, 400, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var foundError apihelpers.RequestError
		json.Unmarshal(responseBody, &foundError)

		expectedMessage := "failed request body deserialization"
		assert.Equal(t, foundError.Message, expectedMessage, "Wrong response body.")
	})

	t.Run("500 on proxy update failure on crud", func(t *testing.T) {
		fieldsToUpdate := proxyservice.CrudProxy{
			BasePath: "/new-base-path",
		}

		crudClient := &mock.CRUD[proxyservice.CrudProxy]{
			PatchError: fmt.Errorf("item update failed"),
		}

		req := GetMockedRequest(
			t,
			http.MethodPatch,
			"/-/proxies",
			CreateRequestBody(t, fieldsToUpdate),
			crudClient,
			config.EnvironmentVariables{},
		)

		vars := map[string]string{
			"id": "proxy-id",
		}
		req = mux.SetURLVars(req, vars)

		w := httptest.NewRecorder()
		UpdateProxyByIdHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, 500, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var foundError apihelpers.RequestError
		json.Unmarshal(responseBody, &foundError)

		expectedMessage := "failed to update proxy"
		assert.Equal(t, foundError.Message, expectedMessage, "Wrong response body.")
	})
	t.Run("200 on successful proxy update", func(t *testing.T) {
		newBasePath := "/new-path"
		newTargetBaseUrl := "https://some-host/"

		fieldsToUpdate := map[string]any{
			"basePath":       newBasePath,
			"targetBaseUrl":  newTargetBaseUrl,
			"clientId":       "",
			"authentication": nil,
		}

		expectedProxy := &proxyservice.CrudProxy{
			BasePath:      "/new-path",
			TargetBaseUrl: "https://some-host/",
			ClientId:      &emptyString,
		}

		expectedPatchBody := crud.PatchBody{
			Set:   map[string]interface{}{"basePath": "/new-path", "targetBaseUrl": "https://some-host/", "clientId": ""},
			Unset: map[string]bool{"authentication": true},
		}

		crudClient := &mock.CRUD[proxyservice.CrudProxy]{
			PatchResult: expectedProxy,
			PatchAssertionFunc: func(_ context.Context, id string, body crud.PatchBody, options crud.Options) {
				require.Equal(t, "proxy-id", id)
				require.Equal(t, expectedPatchBody, body)
			},
		}

		req := GetMockedRequest(
			t,
			http.MethodPatch,
			"/-/proxies",
			CreateRequestBody(t, fieldsToUpdate),
			crudClient,
			config.EnvironmentVariables{},
		)
		vars := map[string]string{
			"id": "proxy-id",
		}
		req = mux.SetURLVars(req, vars)

		w := httptest.NewRecorder()
		UpdateProxyByIdHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, 200, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var response *proxyservice.CrudProxy
		json.Unmarshal(responseBody, &response)

		require.Equal(t, expectedProxy, response, "Wrong response body.")
	})

	t.Run("200 with correct patch body when passing a null value in json", func(t *testing.T) {
		fieldsToUpdateJson := []byte(`{"basePath": "/new-path", "targetBaseUrl": "https://some-host/", "clientId":"", "authentication": null}`)

		expectedProxy := &proxyservice.CrudProxy{
			BasePath:      "/new-path",
			TargetBaseUrl: "https://some-host/",
			ClientId:      &emptyString,
		}

		expectedPatchBody := crud.PatchBody{
			Set:   map[string]interface{}{"basePath": "/new-path", "targetBaseUrl": "https://some-host/", "clientId": ""},
			Unset: map[string]bool{"authentication": true},
		}

		crudClient := &mock.CRUD[proxyservice.CrudProxy]{
			PatchResult: expectedProxy,
			PatchAssertionFunc: func(_ context.Context, id string, body crud.PatchBody, options crud.Options) {
				require.Equal(t, "proxy-id", id)
				require.Equal(t, expectedPatchBody, body)
			},
		}

		req := GetMockedRequest(
			t,
			http.MethodPatch,
			"/-/proxies",
			bytes.NewBuffer(fieldsToUpdateJson),
			crudClient,
			config.EnvironmentVariables{},
		)
		vars := map[string]string{
			"id": "proxy-id",
		}
		req = mux.SetURLVars(req, vars)

		w := httptest.NewRecorder()
		UpdateProxyByIdHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, 200, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var response *proxyservice.CrudProxy
		json.Unmarshal(responseBody, &response)

		require.Equal(t, expectedProxy, response, "Wrong response body.")
	})
}
