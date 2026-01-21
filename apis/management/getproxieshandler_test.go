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
)

func TestGetProxiesHandler(t *testing.T) {
	t.Run("500 on error counting proxies", func(t *testing.T) {
		errorFromCrud := "proxies count failed"
		crudClientMock := &mock.CRUD[proxyservice.CrudProxy]{
			CountError: fmt.Errorf("%s", errorFromCrud),
		}

		req := GetMockedRequest(t, http.MethodGet, "/-/proxies", nil, crudClientMock, config.EnvironmentVariables{})
		w := httptest.NewRecorder()

		GetProxiesHandler(w, req)

		require.Equal(t, w.Result().StatusCode, http.StatusInternalServerError, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var foundError apihelpers.RequestError
		json.Unmarshal(responseBody, &foundError)

		expectedMessage := "failed to retrieve proxies count"
		require.Equal(t, foundError.Message, expectedMessage, "Wrong response body.")
		require.Equal(t, foundError.Error, errorFromCrud, "Wrong response body.")
	})

	t.Run("500 on error retrieving proxies from crud", func(t *testing.T) {
		errorFromCrud := "item retrieval failed"
		crudClientMock := &mock.CRUD[proxyservice.CrudProxy]{
			ListError: fmt.Errorf("%s", errorFromCrud),
		}

		req := GetMockedRequest(t, http.MethodGet, "/-/proxies", nil, crudClientMock, config.EnvironmentVariables{})
		w := httptest.NewRecorder()

		GetProxiesHandler(w, req)

		require.Equal(t, w.Result().StatusCode, http.StatusInternalServerError, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)
		var foundError apihelpers.RequestError
		json.Unmarshal(responseBody, &foundError)

		expectedMessage := "failed to retrieve proxy"
		require.Equal(t, foundError.Message, expectedMessage, "Wrong response body.")
		require.Equal(t, foundError.Error, errorFromCrud, "Wrong response body.")
	})

	t.Run("200 with simple items", func(t *testing.T) {
		issuerUrl := "https://token.issuer/"
		issuerValidationUrl := "https://token-issuer.validator/"
		expectedProxyList := []proxyservice.CrudProxy{
			{
				BasePath:      "/base-path-1",
				TargetBaseUrl: "https://target.url/api/v1",
			},
			{
				BasePath:      "/base-path-2",
				TargetBaseUrl: "https://target.url/api/v2",
			},
			{
				BasePath:                 "/base-path-3",
				TokenIssuerUrl:           &issuerUrl,
				TokenIssuerValidationUrl: &issuerValidationUrl,
			},
		}
		crudClientMock := &mock.CRUD[proxyservice.CrudProxy]{
			ListResult: expectedProxyList,
		}

		req := GetMockedRequest(t, http.MethodGet, "/-/proxies", nil, crudClientMock, config.EnvironmentVariables{})
		w := httptest.NewRecorder()

		GetProxiesHandler(w, req)

		require.Equal(t, w.Result().StatusCode, http.StatusOK, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)

		// NOTE: deserializing to original CRUD item just to simplify assertions
		var items []proxyservice.CrudProxy
		json.Unmarshal(responseBody, &items)
		require.Equal(t, items, expectedProxyList)
	})

	t.Run("200 without secret informations", func(t *testing.T) {
		expectedProxyList := []proxyservice.CrudProxy{
			{
				BasePath:       "/base-path-1",
				TargetBaseUrl:  "https://target.url/api/v1",
				Authentication: &testAuthMethod,
				GrantType:      &testGrantType,
				Username:       &testUsername,
				Password:       &testPassword,
			},
			{
				BasePath:       "/base-path-2",
				TargetBaseUrl:  "https://target.url/api/v2",
				Authentication: &testAuthMethod,
				GrantType:      &testGrantType,
				ClientId:       &testUsername,
				ClientSecret:   &testPassword,
			},
		}
		crudClientMock := &mock.CRUD[proxyservice.CrudProxy]{
			ListResult: expectedProxyList,
			ListAssertionFunc: func(ctx context.Context, options crud.Options) {
				require.Equal(t, options.Filter, crud.Filter{
					Skip:  0,
					Limit: 25,
				})
			},
		}

		req := GetMockedRequest(t, http.MethodGet, "/-/proxies", nil, crudClientMock, config.EnvironmentVariables{})
		w := httptest.NewRecorder()

		GetProxiesHandler(w, req)

		require.Equal(t, w.Result().StatusCode, http.StatusOK, "Wrong status code.")

		// NOTE: deserializing to original CRUD item just to simplify assertions
		var items []proxyservice.CrudProxy
		responseBody, _ := io.ReadAll(w.Result().Body)
		json.Unmarshal(responseBody, &items)
		require.Nil(t, items[0].Password, "")
		require.Nil(t, items[1].ClientSecret, "")
	})

	t.Run("200 with single basePath filter", func(t *testing.T) {
		expectedProxyList := []proxyservice.CrudProxy{
			{
				BasePath:       "/base-path-1",
				TargetBaseUrl:  "https://target.url/api/v1",
				Authentication: &testAuthMethod,
				GrantType:      &testGrantType,
				Username:       &testUsername,
				Password:       &testPassword,
			},
		}
		expectedFilter := crud.Filter{
			MongoQuery: map[string]any{
				"basePath": "base-path-1",
			},
			Skip:  0,
			Limit: 25,
		}
		crudClientMock := &mock.CRUD[proxyservice.CrudProxy]{
			ListResult: expectedProxyList,
			ListAssertionFunc: func(ctx context.Context, options crud.Options) {
				require.Equal(t, options.Filter, expectedFilter)
			},
		}

		req := GetMockedRequest(t, http.MethodGet, "/-/proxies?basePath=base-path-1", nil, crudClientMock, config.EnvironmentVariables{})
		w := httptest.NewRecorder()

		GetProxiesHandler(w, req)

		require.Equal(t, w.Result().StatusCode, http.StatusOK, "Wrong status code.")
	})

	t.Run("200 with multiple basePath filters", func(t *testing.T) {
		expectedProxyList := []proxyservice.CrudProxy{
			{
				BasePath:       "/base-path-1",
				TargetBaseUrl:  "https://target.url/api/v1",
				Authentication: &testAuthMethod,
				GrantType:      &testGrantType,
				Username:       &testUsername,
				Password:       &testPassword,
			},
			{
				BasePath:       "/some-other-base-path-2",
				TargetBaseUrl:  "https://target.url/api/v1",
				Authentication: &testAuthMethod,
				GrantType:      &testGrantType,
				Username:       &testUsername,
				Password:       &testPassword,
			},
		}
		expectedFilter := crud.Filter{
			MongoQuery: mongohelpers.MongoQuery{
				"basePath": mongohelpers.MongoInFilter{
					In: []string{
						"/base-path-1",
						"/some-other-base-path-2",
					},
				},
			},
			Skip:  0,
			Limit: 25,
		}
		crudClientMock := &mock.CRUD[proxyservice.CrudProxy]{
			ListResult: expectedProxyList,
			ListAssertionFunc: func(ctx context.Context, options crud.Options) {
				require.Equal(t, options.Filter, expectedFilter)
			},
		}

		req := GetMockedRequest(t, http.MethodGet, "/-/proxies?basePath=/base-path-1,/some-other-base-path-2", nil, crudClientMock, config.EnvironmentVariables{})
		w := httptest.NewRecorder()

		GetProxiesHandler(w, req)

		require.Equal(t, w.Result().StatusCode, http.StatusOK, "Wrong status code.")

		responseBytes, err := io.ReadAll(w.Result().Body)
		require.Nil(t, err)

		responseItems := []map[string]any{}
		err = json.Unmarshal(responseBytes, &responseItems)
		require.Nil(t, err)

		require.Equal(t, len(expectedProxyList), len(responseItems), "Wrong status code.")
	})

	t.Run("200 with no items matching basePath", func(t *testing.T) {
		expectedProxyList := []proxyservice.CrudProxy{}
		expectedFilter := crud.Filter{
			MongoQuery: map[string]any{
				"basePath": "base-path-1",
			},
			Skip:  0,
			Limit: 25,
		}
		crudClientMock := &mock.CRUD[proxyservice.CrudProxy]{
			ListResult: expectedProxyList,
			ListAssertionFunc: func(ctx context.Context, options crud.Options) {
				require.Equal(t, options.Filter, expectedFilter)
			},
		}

		req := GetMockedRequest(t, http.MethodGet, "/-/proxies?basePath=base-path-1", nil, crudClientMock, config.EnvironmentVariables{})
		w := httptest.NewRecorder()

		GetProxiesHandler(w, req)

		require.Equal(t, w.Result().StatusCode, http.StatusOK, "Wrong status code.")

		var items ProxyListResponse
		responseBody, _ := io.ReadAll(w.Result().Body)
		json.Unmarshal(responseBody, &items)
		require.Equal(t, len(items), 0)
	})

	t.Run("400 on invalid page", func(t *testing.T) {
		req := GetMockedRequest(t, http.MethodGet, "/-/proxies", nil, nil, config.EnvironmentVariables{})
		AddRequestQueryParams(t, req, map[string]string{
			"page":     "0",
			"per_page": "2",
		})

		w := httptest.NewRecorder()
		GetProxiesHandler(w, req)

		require.Equal(t, w.Result().StatusCode, http.StatusBadRequest, "Wrong status code.")
		responseBody, _ := io.ReadAll(w.Result().Body)
		var foundError apihelpers.RequestError
		json.Unmarshal(responseBody, &foundError)

		expectedMessage := "invalid pagination query parameters"
		require.Equal(t, foundError.Message, expectedMessage, "Wrong response body.")
	})

	t.Run("400 on invalid per_page", func(t *testing.T) {
		req := GetMockedRequest(t, http.MethodGet, "/-/proxies", nil, nil, config.EnvironmentVariables{})
		AddRequestQueryParams(t, req, map[string]string{
			"page":     "1",
			"per_page": "-1",
		})

		w := httptest.NewRecorder()
		GetProxiesHandler(w, req)

		require.Equal(t, w.Result().StatusCode, http.StatusBadRequest, "Wrong status code.")
		responseBody, _ := io.ReadAll(w.Result().Body)
		var foundError apihelpers.RequestError
		json.Unmarshal(responseBody, &foundError)

		expectedMessage := "invalid pagination query parameters"
		require.Equal(t, foundError.Message, expectedMessage, "Wrong response body.")
	})

	t.Run("200 with pagination", func(t *testing.T) {
		expectedProxyList := []proxyservice.CrudProxy{
			{
				BasePath:      "/base-path-1",
				TargetBaseUrl: "https://target.url/api/v1",
			},
			{
				BasePath:      "/base-path-2",
				TargetBaseUrl: "https://target.url/api/v2",
			},
		}
		expectedHeaders := http.Header{
			"Content-Type":  []string{"application/json"},
			"X-Total-Items": []string{"6"},
			"X-Total-Pages": []string{"3"},
		}

		expectedFilter := crud.Filter{
			Skip:  4,
			Limit: 2,
		}

		crudClientMock := &mock.CRUD[proxyservice.CrudProxy]{
			ListResult: expectedProxyList,
			ListAssertionFunc: func(ctx context.Context, options crud.Options) {
				require.Equal(t, options.Filter, expectedFilter)
			},
			CountResult: 6,
		}

		req := GetMockedRequest(t, http.MethodGet, "/-/proxies", nil, crudClientMock, config.EnvironmentVariables{})
		AddRequestQueryParams(t, req, map[string]string{
			"page":     "3",
			"per_page": "2",
		})

		w := httptest.NewRecorder()

		GetProxiesHandler(w, req)

		require.Equal(t, w.Result().StatusCode, http.StatusOK, "Wrong status code.")

		responseBody, _ := io.ReadAll(w.Result().Body)

		// NOTE: deserializing to original CRUD item just to simplify assertions
		var items []proxyservice.CrudProxy
		json.Unmarshal(responseBody, &items)
		require.Equal(t, items, expectedProxyList)
		require.Equal(t, expectedHeaders, w.Header())
	})
}

func TestIntegration_GetProxiesHandler(t *testing.T) {
	gock.DisableNetworking()

	t.Cleanup(func() {
		if !gock.IsDone() {
			gock.OffAll()
			t.Fatal("Mocked API has not been called")
		}
		gock.Off()
	})

	t.Run("200 calling crud-service", func(t *testing.T) {
		expectedProxyResponse, _ := json.Marshal([]proxyservice.CrudProxy{
			{
				BasePath:       "/base-path-1",
				TargetBaseUrl:  "https://target.url/api/v1",
				Authentication: &testAuthMethod,
				GrantType:      &testGrantType,
				Username:       &testUsername,
				Password:       &testPassword,
			},
		})

		crudClientMock, _ := crud.NewClient[proxyservice.CrudProxy](crud.ClientOptions{
			BaseURL: "http://crud-service/proxies",
		})

		gock.New("http://crud-service").
			Get("/proxies/count").
			Reply(200)

		gock.New("http://crud-service").
			Get("/proxies/").
			Reply(200).
			JSON(expectedProxyResponse)

		req := GetMockedRequest(t, http.MethodGet, "/-/proxies", nil, crudClientMock, config.EnvironmentVariables{})
		w := httptest.NewRecorder()

		GetProxiesHandler(w, req)

		require.Equal(t, w.Result().StatusCode, http.StatusOK, "Wrong status code.")
	})

	t.Run("200 with basePath query param filter", func(t *testing.T) {
		expectedProxyResponse, _ := json.Marshal([]proxyservice.CrudProxy{
			{
				BasePath:       "/base-path-1",
				TargetBaseUrl:  "https://target.url/api/v1",
				Authentication: &testAuthMethod,
				GrantType:      &testGrantType,
				Username:       &testUsername,
				Password:       &testPassword,
			},
		})

		crudClientMock, _ := crud.NewClient[proxyservice.CrudProxy](crud.ClientOptions{
			BaseURL: "http://crud-service/proxies",
		})

		gock.New("http://crud-service").
			Get("/proxies/count").
			Reply(200)

		gock.New("http://crud-service").
			Get("/proxies/").
			AddMatcher(getGockBasePathMatcher("base-path-1")).
			Reply(200).
			JSON(expectedProxyResponse)

		req := GetMockedRequest(t, http.MethodGet, "/-/proxies?basePath=base-path-1", nil, crudClientMock, config.EnvironmentVariables{})
		w := httptest.NewRecorder()

		GetProxiesHandler(w, req)

		require.Equal(t, w.Result().StatusCode, http.StatusOK, "Wrong status code.")
		responseBytes, err := io.ReadAll(w.Result().Body)
		require.Nil(t, err)

		var responseList []map[string]any
		err = json.Unmarshal(responseBytes, &responseList)
		require.Nil(t, err)

		expectedResponse := []map[string]any{
			{
				"basePath":       "/base-path-1",
				"targetBaseUrl":  "https://target.url/api/v1",
				"authentication": "oauth2",
				"username":       "SomeUsername",
				"grantType":      "password",
			},
		}

		require.Equal(t, expectedResponse, responseList)

		require.Nil(t, responseList[0]["authType"])
		require.Nil(t, responseList[0]["clientId"])
		require.Nil(t, responseList[0]["clientSecret"])
		require.Nil(t, responseList[0]["password"])
	})
}

func getGockBasePathMatcher(basePath string) gock.MatchFunc {
	proxyMatcher := func(req *http.Request, greq *gock.Request) (bool, error) {
		rawQuery := req.URL.Query().Get("_q")
		if rawQuery != fmt.Sprintf(`{"basePath":"%s"}`, basePath) {
			return false, fmt.Errorf("basePath in query '%s' not matching expected basePath: %s", rawQuery, basePath)
		}

		return true, nil
	}

	return proxyMatcher
}
