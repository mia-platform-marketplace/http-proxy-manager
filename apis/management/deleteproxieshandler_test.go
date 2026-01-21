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
	"testing"

	apihelpers "proxy-manager/apis/helpers"
	"proxy-manager/internal/config"
	"proxy-manager/internal/mongohelpers"
	proxyservice "proxy-manager/services/proxies"

	"github.com/mia-platform/go-crud-service-client"
	"github.com/mia-platform/go-crud-service-client/testhelper/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"
	"gotest.tools/assert"
)

func TestDeleteProxiesHandler(t *testing.T) {
	t.Run("400 on query params not specified", func(t *testing.T) {
		crudClientMock := &mock.CRUD[proxyservice.CrudProxy]{}

		req := GetMockedRequest(t, http.MethodDelete, "/-/proxies", nil, crudClientMock, config.EnvironmentVariables{})
		w := httptest.NewRecorder()

		DeleteProxiesHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusBadRequest, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var foundError apihelpers.RequestError
		json.Unmarshal(responseBody, &foundError)

		expectedMessage := "exactly one between basePath and basePathPrefix must be specified"
		assert.Equal(t, foundError.Message, expectedMessage, "Wrong error message.")
		assert.Equal(t, foundError.Error, expectedMessage, "Wrong error.")
	})

	t.Run("400 on both basePath and basePathPrefix specified", func(t *testing.T) {
		crudClientMock := &mock.CRUD[proxyservice.CrudProxy]{}

		testBasePath := "/base-path"
		testBasePathPrefix := "/some-prefix"
		req := GetMockedRequest(t, http.MethodDelete, "/-/proxies", nil, crudClientMock, config.EnvironmentVariables{})
		AddRequestQueryParams(t, req, map[string]string{"basePath": testBasePath, "basePathPrefix": testBasePathPrefix})
		w := httptest.NewRecorder()

		DeleteProxiesHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusBadRequest, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var foundError apihelpers.RequestError
		json.Unmarshal(responseBody, &foundError)

		expectedMessage := "exactly one between basePath and basePathPrefix must be specified"
		assert.Equal(t, foundError.Message, expectedMessage, "Wrong error message.")
		assert.Equal(t, foundError.Error, expectedMessage, "Wrong error.")
	})

	t.Run("500 on crud error", func(t *testing.T) {
		errorFromCrud := "item deletion failed"
		crudClientMock := &mock.CRUD[proxyservice.CrudProxy]{
			DeleteManyError: fmt.Errorf("%s", errorFromCrud),
		}

		req := GetMockedRequest(t, http.MethodDelete, "/-/proxies", nil, crudClientMock, config.EnvironmentVariables{})
		AddRequestQueryParams(t, req, map[string]string{"basePath": "/basepath-to-delete"})
		w := httptest.NewRecorder()

		DeleteProxiesHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusInternalServerError, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var foundError apihelpers.RequestError
		json.Unmarshal(responseBody, &foundError)

		expectedMessage := "failed to delete proxies"
		assert.Equal(t, foundError.Message, expectedMessage, "Wrong response body.")
		assert.Equal(t, foundError.Error, errorFromCrud, "Wrong response body.")
	})

	t.Run("204 on delete success - with basePath query param", func(t *testing.T) {
		expectedFilter := crud.Filter{
			MongoQuery: map[string]any{
				"basePath": "/basepath-to-delete",
			},
		}
		crudClientMock := &mock.CRUD[proxyservice.CrudProxy]{
			DeleteManyResult: 1,
			DeleteManyAssertionFunc: func(ctx context.Context, options crud.Options) {
				assert.DeepEqual(t, options.Filter, expectedFilter)
			},
		}

		req := GetMockedRequest(t, http.MethodDelete, "/-/proxies", nil, crudClientMock, config.EnvironmentVariables{})
		AddRequestQueryParams(t, req, map[string]string{"basePath": "/basepath-to-delete"})
		w := httptest.NewRecorder()

		DeleteProxiesHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusNoContent, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var response any
		json.Unmarshal(responseBody, &response)
		require.Nil(t, response)
	})

	t.Run("204 on delete success - with basePathPrefix query param", func(t *testing.T) {
		expectedFilter := crud.Filter{
			MongoQuery: mongohelpers.MongoQuery{
				"basePath": mongohelpers.MongoRegex{Regex: "^/common-prefix/"},
			},
		}
		crudClientMock := &mock.CRUD[proxyservice.CrudProxy]{
			DeleteManyResult: 1,
			DeleteManyAssertionFunc: func(ctx context.Context, options crud.Options) {
				assert.DeepEqual(t, options.Filter, expectedFilter)
			},
		}

		req := GetMockedRequest(t, http.MethodDelete, "/-/proxies", nil, crudClientMock, config.EnvironmentVariables{})
		AddRequestQueryParams(t, req, map[string]string{"basePathPrefix": "/common-prefix"})
		w := httptest.NewRecorder()

		DeleteProxiesHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusNoContent, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var response any
		json.Unmarshal(responseBody, &response)
		require.Nil(t, response)
	})
}

func TestIntegration_DeleteProxiesHandler(t *testing.T) {
	gock.DisableNetworking()

	t.Cleanup(func() {
		if !gock.IsDone() {
			gock.OffAll()
			t.Fatal("Mocked API has not been called")
		}
		gock.Off()
	})

	t.Run("200 calling crud-service with basePath query param", func(t *testing.T) {
		testBasePath := "/basepath-to-delete"
		crudClientMock, _ := crud.NewClient[proxyservice.CrudProxy](crud.ClientOptions{
			BaseURL: "http://crud-service/proxies",
		})

		gock.New("http://crud-service").
			Delete("/proxies").
			AddMatcher(func(req *http.Request, greq *gock.Request) (bool, error) {
				rawQuery := req.URL.Query().Get("_q")
				if rawQuery != fmt.Sprintf(`{"basePath":"%s"}`, testBasePath) {
					return false, fmt.Errorf("basePath in query %s not matching expected basePath: %s", rawQuery, testBasePath)
				}

				return true, nil
			}).
			Reply(200)

		req := GetMockedRequest(t, http.MethodDelete, "/-/proxies", nil, crudClientMock, config.EnvironmentVariables{})
		AddRequestQueryParams(t, req, map[string]string{"basePath": testBasePath})
		w := httptest.NewRecorder()

		DeleteProxiesHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusNoContent, "Wrong status code.")
	})

	t.Run("200 calling crud-service with basePathPrefix query param", func(t *testing.T) {
		testBasePath := "/common-basePath"
		crudClientMock, _ := crud.NewClient[proxyservice.CrudProxy](crud.ClientOptions{
			BaseURL: "http://crud-service/proxies",
		})

		gock.New("http://crud-service").
			Delete("/proxies").
			AddMatcher(func(req *http.Request, greq *gock.Request) (bool, error) {
				rawQuery := req.URL.Query().Get("_q")
				if rawQuery != fmt.Sprintf(`{"basePath":{"$regex":"^%s/"}}`, testBasePath) {
					return false, fmt.Errorf("basePath in query %s not matching expected basePath: %s", rawQuery, testBasePath)
				}

				return true, nil
			}).
			Reply(200)

		req := GetMockedRequest(t, http.MethodDelete, "/-/proxies", nil, crudClientMock, config.EnvironmentVariables{})
		AddRequestQueryParams(t, req, map[string]string{"basePathPrefix": testBasePath})
		w := httptest.NewRecorder()

		DeleteProxiesHandler(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusNoContent, "Wrong status code.")
	})
}
