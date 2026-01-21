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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"proxy-manager/entities"
	"proxy-manager/internal/config"
	"proxy-manager/internal/pathextractor"
	allowedtargets_repository "proxy-manager/repositories/allowedtargets"
	allowedtargets_service "proxy-manager/services/allowedtargets"
	auth "proxy-manager/services/authentication"
	proxyservice "proxy-manager/services/proxies"

	glogrus "github.com/mia-platform/glogger/v4/loggers/logrus"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"gopkg.in/h2non/gock.v1"
	"gotest.tools/assert"
)

var accessToken = auth.AccessToken{
	AccessToken: "abcde",
	ExpiresIn:   json.RawMessage(`60`),
	Scope:       "write:users read:users",
	TokenType:   "bearer",
}

var defaultRepo, _ = allowedtargets_repository.FromENV(config.EnvironmentVariables{})
var defaultContext = allowedtargets_service.RegisterInstance(
	context.Background(),
	allowedtargets_service.New(defaultRepo),
)

func TestProxyHandler(t *testing.T) {
	t.Run("200 proxy request with no authentication", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL, nil)

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  s.URL,
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with no authentication - all headers proxied by default", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// verify that all the original request headers were forwarded
			assert.Equal(t, req.Header.Get("Content-Type"), "application/json")
			assert.Equal(t, req.Header.Get("Accept"), "*/*")
			assert.Equal(t, req.Header.Get("X-Real-IP"), "1.1.1.1")
			assert.Equal(t, req.Header.Get("X-Custom-Header"), "my-custom-header")

			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL, nil)

		// add headers to original request
		request.Header.Set("Accept", "*/*")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Real-IP", "1.1.1.1")
		request.Header.Set("X-Custom-Header", "my-custom-header")

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  s.URL,
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with no authentication - add additional headers", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// verify that all the original request headers were forwarded
			assert.Equal(t, req.Header.Get("Content-Type"), "application/json")
			assert.Equal(t, req.Header.Get("Accept"), "*/*")
			assert.Equal(t, req.Header.Get("X-Real-IP"), "1.1.1.1")
			assert.Equal(t, req.Header.Get("X-Custom-Header"), "my-custom-header")
			assert.Equal(t, req.Header.Get("x-api-key"), "custom-api-key")

			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL, nil)

		// add headers to original request
		request.Header.Set("Accept", "*/*")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Real-IP", "1.1.1.1")
		request.Header.Set("X-Custom-Header", "my-custom-header")

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  s.URL,
			AdditionalHeaders: []entities.AdditionalHeader{
				{Name: "x-api-key", Value: "custom-api-key"},
			},
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with no authentication - query parameters proxied", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			assert.Equal(t, req.URL.RawQuery, "key=value&chiave=valore")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL+"?key=value&chiave=valore", nil)

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  s.URL,
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with no authentication - path parameters and one-level basePath", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, req.URL.Path, "/test-page", "Wrong request")
			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL+"/test-page", nil)

		proxyConfig := entities.Proxy{
			Authentication:           "none",
			TargetBaseUrl:            s.URL + "/{pageId}",
			BasePath:                 "/{pageId}",
			TokenIssuerValidationUrl: "issuervalidationtest.com/test",
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with no authentication - path parameters and two-levels basePath", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, req.URL.Path, "/test-page", "Wrong request")
			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL+"/docs/test-page", nil)

		proxyConfig := entities.Proxy{
			Authentication:           "none",
			TargetBaseUrl:            s.URL + "/{pageId}",
			BasePath:                 "/docs/{pageId}",
			TokenIssuerValidationUrl: "issuervalidationtest.com/test",
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with no authentication - all headers proxied by default - with query parameters", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// verify that all the original request headers were forwarded
			assert.Equal(t, req.Header.Get("Content-Type"), "application/json")
			assert.Equal(t, req.Header.Get("Accept"), "*/*")
			assert.Equal(t, req.Header.Get("X-Real-IP"), "1.1.1.1")
			assert.Equal(t, req.Header.Get("X-Custom-Header"), "my-custom-header")

			assert.Equal(t, req.URL.RawQuery, "key=value&chiave=valore")

			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL+"?key=value&chiave=valore", nil)

		// add headers to original request
		request.Header.Set("Accept", "*/*")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Real-IP", "1.1.1.1")
		request.Header.Set("X-Custom-Header", "my-custom-header")

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  s.URL,
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with no authentication - no headers proxied due to empty list", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// verify that no original request headers were forwarded
			assert.Equal(t, req.Header.Get("Content-Type"), "")
			assert.Equal(t, req.Header.Get("Accept"), "")
			assert.Equal(t, req.Header.Get("X-Real-IP"), "")
			assert.Equal(t, req.Header.Get("X-Custom-Header"), "")

			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL, nil)

		// add headers to original request
		request.Header.Set("Accept", "*/*")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Real-IP", "1.1.1.1")
		request.Header.Set("X-Custom-Header", "my-custom-header")

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  s.URL,
			HeadersToProxy: []string{},
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with no authentication - only selected headers proxied", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// verify that only selected headers were forwarded
			assert.Equal(t, req.Header.Get("Content-Type"), "application/json")
			assert.Equal(t, req.Header.Get("Accept"), "*/*")
			assert.Equal(t, req.Header.Get("X-Real-IP"), "", "this header should not be forwarded")
			assert.Equal(t, req.Header.Get("X-Custom-Header"), "", "this header should not be forwarded")
			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL, nil)

		// add headers to original request
		request.Header.Set("Accept", "*/*")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Real-IP", "1.1.1.1")
		request.Header.Set("X-Custom-Header", "my-custom-header")

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  s.URL,
			HeadersToProxy: []string{"Accept", "Content-Type"},
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with token authentication", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()

			authHeader := "Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw=="
			assert.Equal(t, req.Header.Get("Content-Type"), "application/x-www-form-urlencoded", "Unexpected content type")
			assert.Equal(t, req.Header.Get("Authorization"), authHeader, "Unexpected auth header")
			requestBodyBytes, err := io.ReadAll(req.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			expectedBody := "grant_type=client_credentials"
			assert.Equal(t, string(requestBodyBytes), expectedBody, "Unexpected request body found")

			payload, err := json.Marshal(accessToken)
			assert.Equal(t, err, nil, "Unexpected error")
			w.WriteHeader(http.StatusOK)
			w.Write(payload)
		}))
		defer tokenServer.Close()

		user := `{"user": "me", "groups": ["admin", "users"]}`
		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, req.Header.Get("Authorization"), "Bearer abcde")
			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer resourceServer.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, resourceServer.URL, nil)

		proxyConfig := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: tokenServer.URL,
			TargetBaseUrl:  resourceServer.URL,
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with token authentication - with query parameters", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()

			authHeader := "Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw=="
			assert.Equal(t, req.Header.Get("Content-Type"), "application/x-www-form-urlencoded", "Unexpected content type")
			assert.Equal(t, req.Header.Get("Authorization"), authHeader, "Unexpected auth header")
			requestBodyBytes, err := io.ReadAll(req.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			expectedBody := "grant_type=client_credentials"
			assert.Equal(t, string(requestBodyBytes), expectedBody, "Unexpected request body found")

			payload, err := json.Marshal(accessToken)
			assert.Equal(t, err, nil, "Unexpected error")
			w.WriteHeader(http.StatusOK)
			w.Write(payload)
		}))
		defer tokenServer.Close()

		user := `{"user": "me", "groups": ["admin", "users"]}`
		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, req.Header.Get("Authorization"), "Bearer abcde")
			w.Header().Set("Content-Type", "application/json")

			assert.Equal(t, req.URL.RawQuery, "key=value&chiave=valore")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer resourceServer.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, resourceServer.URL+"?key=value&chiave=valore", nil)

		proxyConfig := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: tokenServer.URL,
			TargetBaseUrl:  resourceServer.URL,
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with token refresh", func(t *testing.T) {
		expiredToken := auth.AccessToken{
			AccessToken: "expired",
			ExpiresIn:   json.RawMessage(`60`),
			Scope:       "write:users read:users",
			TokenType:   "bearer",
		}

		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()

			authHeader := "Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw=="
			assert.Equal(t, req.Header.Get("Content-Type"), "application/x-www-form-urlencoded", "Unexpected content type")
			assert.Equal(t, req.Header.Get("Authorization"), authHeader, "Unexpected auth header")

			requestBodyBytes, err := io.ReadAll(req.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			expectedBody := "grant_type=client_credentials"
			assert.Equal(t, string(requestBodyBytes), expectedBody, "Unexpected request body found")

			payload, err := json.Marshal(accessToken)
			assert.Equal(t, err, nil, "Unexpected error")
			w.WriteHeader(http.StatusOK)
			w.Write(payload)
		}))
		defer tokenServer.Close()

		user := `{"user": "me", "groups": ["admin", "users"]}`
		body := `{"test_id": "test_value"}`

		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			authHeader := req.Header.Get("Authorization")
			if authHeader == "Bearer expired" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			assert.Equal(t, authHeader, "Bearer abcde")

			requestBodyBytes, err := io.ReadAll(req.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			assert.Equal(t, string(requestBodyBytes), body, "Unexpected request body found")

			w.Header().Set("Content-Type", "application/json")

			_, err = w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer resourceServer.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodPost, resourceServer.URL, strings.NewReader(body))

		proxyConfig := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: tokenServer.URL,
			TargetBaseUrl:  resourceServer.URL,
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)
		tokensCache.SetCachedToken(resourceServer.URL, expiredToken)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with token refresh - also when 403 is obtained", func(t *testing.T) {
		expiredToken := auth.AccessToken{
			AccessToken: "expired",
			ExpiresIn:   json.RawMessage(`60`),
			Scope:       "write:users read:users",
			TokenType:   "bearer",
		}

		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()

			authHeader := "Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw=="
			assert.Equal(t, req.Header.Get("Content-Type"), "application/x-www-form-urlencoded", "Unexpected content type")
			assert.Equal(t, req.Header.Get("Authorization"), authHeader, "Unexpected auth header")

			requestBodyBytes, err := io.ReadAll(req.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			expectedBody := "grant_type=client_credentials"
			assert.Equal(t, string(requestBodyBytes), expectedBody, "Unexpected request body found")

			payload, err := json.Marshal(accessToken)
			assert.Equal(t, err, nil, "Unexpected error")
			w.WriteHeader(http.StatusOK)
			w.Write(payload)
		}))
		defer tokenServer.Close()

		user := `{"user": "me", "groups": ["admin", "users"]}`
		body := `{"test_id": "test_value"}`

		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			authHeader := req.Header.Get("Authorization")
			if authHeader == "Bearer expired" {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			assert.Equal(t, authHeader, "Bearer abcde")

			requestBodyBytes, err := io.ReadAll(req.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			assert.Equal(t, string(requestBodyBytes), body, "Unexpected request body found")

			w.Header().Set("Content-Type", "application/json")

			_, err = w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer resourceServer.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodPost, resourceServer.URL, strings.NewReader(body))

		proxyConfig := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: tokenServer.URL,
			TargetBaseUrl:  resourceServer.URL,
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)
		tokensCache.SetCachedToken(resourceServer.URL, expiredToken)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("500 token server returns error", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()

			authHeader := "Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw=="
			assert.Equal(t, req.Header.Get("Content-Type"), "application/x-www-form-urlencoded", "Unexpected content type")
			assert.Equal(t, req.Header.Get("Authorization"), authHeader, "Unexpected auth header")

			requestBodyBytes, err := io.ReadAll(req.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			expectedBody := "grant_type=client_credentials"
			assert.Equal(t, string(requestBodyBytes), expectedBody, "Unexpected request body found")

			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer tokenServer.Close()

		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
		defer resourceServer.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, resourceServer.URL, nil)

		proxyConfig := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: tokenServer.URL,
			TargetBaseUrl:  resourceServer.URL,
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 500, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), "unexpected status code on token request: 500", "Wrong response body.")
	})

	t.Run("500 resource server returns error", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()

			authHeader := "Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw=="
			assert.Equal(t, req.Header.Get("Content-Type"), "application/x-www-form-urlencoded", "Unexpected content type")
			assert.Equal(t, req.Header.Get("Authorization"), authHeader, "Unexpected auth header")

			requestBodyBytes, err := io.ReadAll(req.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			expectedBody := "grant_type=client_credentials"
			assert.Equal(t, string(requestBodyBytes), expectedBody, "Unexpected request body found")

			payload, err := json.Marshal(accessToken)
			assert.Equal(t, err, nil, "Unexpected error")
			w.WriteHeader(http.StatusOK)
			w.Write(payload)
		}))
		defer tokenServer.Close()

		resourceServerResponse := []byte("an error occurred")
		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, req.Header.Get("Authorization"), "Bearer abcde")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(resourceServerResponse)
		}))
		defer resourceServer.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, resourceServer.URL, nil)

		proxyConfig := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: tokenServer.URL,
			TargetBaseUrl:  resourceServer.URL,
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 500, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), string(resourceServerResponse), "Wrong response body.")
	})

	t.Run("follows redirects on 3XX response", func(t *testing.T) {
		defer gock.Off()

		testHost := "https://my-service"
		testRedirectHost := "http://unsafe-redirect"
		testApiPath := "/api"

		gock.DisableNetworking()
		gock.
			New(testHost).
			Get(testApiPath).
			ReplyFunc(func(r *gock.Response) {
				r.SetHeader("location", fmt.Sprintf("%s%s", testRedirectHost, testApiPath))
				r.Status(http.StatusPermanentRedirect)
			})

		user := `{"user": "me", "groups": ["admin", "users"]}`
		gock.
			New(testRedirectHost).
			Get(testApiPath).
			Reply(http.StatusOK).
			JSON(user)

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, testHost, nil)

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  fmt.Sprintf("%s%s", testHost, testApiPath),
		}

		env := config.EnvironmentVariables{}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, gock.IsDone(), true)
	})

	t.Run("200 allowed Content-Type of the target service response", func(t *testing.T) {
		testCase := []struct {
			contentType            string
			disallowedContentTypes []string
		}{
			{contentType: "text/html"},
			{contentType: "Text/HTML"},
			{contentType: "text/html;charset=utf-8"},
			{contentType: "text/html;charset=UTF-8"},
			{contentType: "Text/HTML;Charset=utf-8"},
			{contentType: "text/html; charset=utf-8"},
			{contentType: "text/html; charset=ISO-8859-4"},
			{contentType: "application/javascript"},
			{contentType: "text/javascript"},
			{contentType: "application/json"},
			{contentType: "application/json", disallowedContentTypes: []string{"text/html", "text/javascript", "application/javascript"}},
		}

		testHost := "https://my-service"
		testApiPath := "/api"

		for i, testCase := range testCase {
			env := config.EnvironmentVariables{}
			env.DisallowedResponseContentTypes = testCase.disallowedContentTypes

			t.Run(fmt.Sprintf("test case #%d - Content-Type: %s - disallowedContentTypes: %s", i+1, testCase.contentType, strings.Join(testCase.disallowedContentTypes, ", ")), func(t *testing.T) {

				defer gock.Off()

				gock.
					New(testHost).
					Get(testApiPath).
					ReplyFunc(func(r *gock.Response) {
						r.SetHeader("Content-Type", testCase.contentType)
						r.Status(http.StatusOK)
					})

				recorder := httptest.NewRecorder()
				request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, testHost, nil)

				proxyConfig := entities.Proxy{
					Authentication: "none",
					TargetBaseUrl:  fmt.Sprintf("%s%s", testHost, testApiPath),
				}

				tokensCache := auth.NewTokensCache(30)

				ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

				assert.Equal(t, recorder.Code, 200)
				assert.Equal(t, gock.IsDone(), true)
			})
		}
	})

	t.Run("500 disallowed Content-Type of the target service response", func(t *testing.T) {
		testCases := []struct {
			contentType string
		}{
			{contentType: "text/html"},
			{contentType: "Text/HTML"},
			{contentType: "text/html;charset=utf-8"},
			{contentType: "text/html;charset=UTF-8"},
			{contentType: "Text/HTML;Charset=utf-8"},
			{contentType: "text/html; charset=utf-8"},
			{contentType: "text/html; charset=ISO-8859-4"},
			{contentType: "application/javascript"},
			{contentType: "text/javascript"},
		}

		testHost := "https://my-service"
		testApiPath := "/api"

		disallowedContentTypes := []string{"text/html", "text/javascript", "application/javascript"}

		env := config.EnvironmentVariables{DisallowedResponseContentTypes: disallowedContentTypes}

		for i, testCase := range testCases {

			t.Run(fmt.Sprintf("test case #%d - Content-Type: %s - disallowedContentTypes: %s", i+1, testCase.contentType, strings.Join(disallowedContentTypes, ", ")), func(t *testing.T) {

				defer gock.Off()

				gock.
					New(testHost).
					Get(testApiPath).
					ReplyFunc(func(r *gock.Response) {
						r.SetHeader("Content-Type", testCase.contentType)
						r.Status(http.StatusOK)
					})

				recorder := httptest.NewRecorder()
				request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, testHost, nil)

				proxyConfig := entities.Proxy{
					Authentication: "none",
					TargetBaseUrl:  fmt.Sprintf("%s%s", testHost, testApiPath),
				}

				tokensCache := auth.NewTokensCache(30)

				ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

				assert.Equal(t, recorder.Code, 500)
				assert.Equal(t, recorder.Body.String(), `{"message":"Content-Type of the target service response not allowed"}`)
				assert.Equal(t, gock.IsDone(), true)
			})
		}
	})

	t.Run("500 on target url not allowed", func(t *testing.T) {
		env := config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				"https://apis.target.com",
			},
		}
		repo, err := allowedtargets_repository.FromENV(env)
		assert.NilError(t, err)
		context := allowedtargets_service.RegisterInstance(
			context.Background(),
			allowedtargets_service.New(repo),
		)
		defer gock.Off()

		gock.
			New("https://not-allowed-target.com").
			Get("/api").
			ReplyFunc(func(r *gock.Response) {
				r.Status(http.StatusOK)
			})

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(context, http.MethodGet, "/", nil)

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  "https://not-allowed-target.com/api",
		}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 500)
		assert.Equal(t, recorder.Body.String(), `specified target URL is not allowed`)
		assert.Equal(t, gock.IsDone(), false)
	})

	t.Run("500 - with authentication - on target url not allowed", func(t *testing.T) {
		env := config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				"https://apis.target.com",
			},
		}
		repo, err := allowedtargets_repository.FromENV(env)
		assert.NilError(t, err)
		context := allowedtargets_service.RegisterInstance(
			context.Background(),
			allowedtargets_service.New(repo),
		)

		defer gock.Off()

		gock.
			New("https://not-allowed-target.com").
			Get("/api").
			ReplyFunc(func(r *gock.Response) {
				r.Status(http.StatusOK)
			})

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(context, http.MethodGet, "/", nil)

		proxyConfig := entities.Proxy{
			Authentication: "oauth2",
			GrantType:      "password",
			Username:       "user",
			Password:       "pass",
			TargetBaseUrl:  "https://not-allowed-target.com/api",
		}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 500)
		assert.Equal(t, recorder.Body.String(), `specified target URL is not allowed`)
		assert.Equal(t, gock.IsDone(), false)
	})

	t.Run("200 on target url allowed", func(t *testing.T) {
		env := config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				"https://apis.target.com",
			},
		}
		repo, err := allowedtargets_repository.FromENV(env)
		assert.NilError(t, err)
		context := allowedtargets_service.RegisterInstance(
			context.Background(),
			allowedtargets_service.New(repo),
		)

		gock.
			New("https://apis.target.com").
			Get("/api").
			ReplyFunc(func(r *gock.Response) {
				r.Status(http.StatusOK)
			})
		defer gock.Off()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(context, http.MethodGet, "/api", nil)

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  "https://apis.target.com",
		}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200)
		assert.Equal(t, gock.IsDone(), true)
	})

	t.Run("200 - with authentication - on target url allowed", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()

			authHeader := "Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw=="
			assert.Equal(t, req.Header.Get("Content-Type"), "application/x-www-form-urlencoded", "Unexpected content type")
			assert.Equal(t, req.Header.Get("Authorization"), authHeader, "Unexpected auth header")
			requestBodyBytes, err := io.ReadAll(req.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			expectedBody := "grant_type=client_credentials"
			assert.Equal(t, string(requestBodyBytes), expectedBody, "Unexpected request body found")

			payload, err := json.Marshal(accessToken)
			assert.Equal(t, err, nil, "Unexpected error")
			w.WriteHeader(http.StatusOK)
			w.Write(payload)
		}))
		defer tokenServer.Close()

		user := `{"user": "me", "groups": ["admin", "users"]}`
		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, req.Header.Get("Authorization"), "Bearer abcde")
			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer resourceServer.Close()

		env := config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				resourceServer.URL,
			},
		}
		repo, err := allowedtargets_repository.FromENV(env)
		assert.NilError(t, err)
		context := allowedtargets_service.RegisterInstance(
			context.Background(),
			allowedtargets_service.New(repo),
		)

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(context, http.MethodGet, resourceServer.URL, nil)

		proxyConfig := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: tokenServer.URL,
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
			TargetBaseUrl:  resourceServer.URL,
		}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})
}

func TestProxyHandlerOptimized(t *testing.T) {
	t.Run("200 proxy request with no authentication", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL, nil)

		proxyConfig := entities.Proxy{
			Authentication:           "none",
			TargetBaseUrl:            s.URL,
			TokenIssuerValidationUrl: "issuervalidationtest.com/test",
		}

		env := config.EnvironmentVariables{AllowProxyOptimizer: true}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with no authentication, with query parameters", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL+"?key=value&chiave=valore", nil)

		proxyConfig := entities.Proxy{
			Authentication:           "none",
			TargetBaseUrl:            s.URL,
			TokenIssuerValidationUrl: "issuervalidationtest.com/test",
		}

		env := config.EnvironmentVariables{AllowProxyOptimizer: true}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with no authentication, with path parameters and one-level basePath", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, req.URL.Path, "/test-page", "Wrong request")
			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL+"/test-page", nil)

		proxyConfig := entities.Proxy{
			Authentication:           "none",
			TargetBaseUrl:            s.URL + "/{pageId}",
			BasePath:                 "/{pageId}",
			TokenIssuerValidationUrl: "issuervalidationtest.com/test",
		}

		env := config.EnvironmentVariables{AllowProxyOptimizer: true}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with no authentication, with path parameters and two-levels basePath", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, req.URL.Path, "/test-page", "Wrong request")
			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL+"/docs/test-page", nil)

		proxyConfig := entities.Proxy{
			Authentication:           "none",
			TargetBaseUrl:            s.URL + "/{pageId}",
			BasePath:                 "/docs/{pageId}",
			TokenIssuerValidationUrl: "issuervalidationtest.com/test",
		}

		env := config.EnvironmentVariables{AllowProxyOptimizer: true}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with no authentication - all headers proxied by default", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// verify that all the original request headers were forwarded
			assert.Equal(t, req.Header.Get("Content-Type"), "application/json")
			assert.Equal(t, req.Header.Get("Accept"), "*/*")
			assert.Equal(t, req.Header.Get("X-Real-IP"), "1.1.1.1")
			assert.Equal(t, req.Header.Get("X-Custom-Header"), "my-custom-header")

			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL, nil)

		// add headers to original request
		request.Header.Set("Accept", "*/*")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Real-IP", "1.1.1.1")
		request.Header.Set("X-Custom-Header", "my-custom-header")

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  s.URL,
		}

		env := config.EnvironmentVariables{AllowProxyOptimizer: true}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with no authentication - no headers proxied due to empty list", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// verify that no original request headers were forwarded
			assert.Equal(t, req.Header.Get("Content-Type"), "")
			assert.Equal(t, req.Header.Get("Accept"), "")
			assert.Equal(t, req.Header.Get("X-Real-IP"), "")
			assert.Equal(t, req.Header.Get("X-Custom-Header"), "")

			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL, nil)

		// add headers to original request
		request.Header.Set("Accept", "*/*")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Real-IP", "1.1.1.1")
		request.Header.Set("X-Custom-Header", "my-custom-header")

		proxyConfig := entities.Proxy{
			Authentication:           "none",
			TargetBaseUrl:            s.URL,
			HeadersToProxy:           []string{},
			TokenIssuerValidationUrl: "issuervalidationtest.com/test",
		}

		env := config.EnvironmentVariables{AllowProxyOptimizer: true}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with no authentication - only selected headers proxied", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// verify that only selected headers were forwarded
			assert.Equal(t, req.Header.Get("Content-Type"), "application/json")
			assert.Equal(t, req.Header.Get("Accept"), "*/*")
			assert.Equal(t, req.Header.Get("X-Real-IP"), "", "this header should not be forwarded")
			assert.Equal(t, req.Header.Get("X-Custom-Header"), "", "this header should not be forwarded")
			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL, nil)

		// add headers to original request
		request.Header.Set("Accept", "*/*")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Real-IP", "1.1.1.1")
		request.Header.Set("X-Custom-Header", "my-custom-header")

		proxyConfig := entities.Proxy{
			Authentication:           "none",
			TargetBaseUrl:            s.URL,
			TokenIssuerValidationUrl: "issuervalidationtest.com/test",
			HeadersToProxy:           []string{"Accept", "Content-Type"},
		}

		env := config.EnvironmentVariables{AllowProxyOptimizer: true}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)
		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with token authentication", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()

			authHeader := "Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw=="
			assert.Equal(t, req.Header.Get("Content-Type"), "application/x-www-form-urlencoded", "Unexpected content type")
			assert.Equal(t, req.Header.Get("Authorization"), authHeader, "Unexpected auth header")

			requestBodyBytes, err := io.ReadAll(req.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			expectedBody := "grant_type=client_credentials"
			assert.Equal(t, string(requestBodyBytes), expectedBody, "Unexpected request body found")

			payload, err := json.Marshal(accessToken)
			assert.Equal(t, err, nil, "Unexpected error")
			w.WriteHeader(http.StatusOK)
			w.Write(payload)
		}))
		defer tokenServer.Close()

		user := `{"user": "me", "groups": ["admin", "users"]}`
		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, req.Header.Get("Authorization"), "Bearer abcde")
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer resourceServer.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, resourceServer.URL, nil)

		proxyConfig := entities.Proxy{
			Authentication:           "oauth2",
			ClientId:                 "6779ef20e75817b79602",
			ClientSecret:             "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl:           tokenServer.URL,
			TargetBaseUrl:            resourceServer.URL,
			GrantType:                "client_credentials",
			TokenIssuerValidationUrl: "issuervalidationtest.com/test",
			AuthType:                 "client_secret_basic",
		}

		env := config.EnvironmentVariables{AllowProxyOptimizer: true}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)
		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with token authentication, with query parameters", func(t *testing.T) {
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()

			authHeader := "Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw=="
			assert.Equal(t, req.Header.Get("Content-Type"), "application/x-www-form-urlencoded", "Unexpected content type")
			assert.Equal(t, req.Header.Get("Authorization"), authHeader, "Unexpected auth header")

			requestBodyBytes, err := io.ReadAll(req.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			expectedBody := "grant_type=client_credentials"
			assert.Equal(t, string(requestBodyBytes), expectedBody, "Unexpected request body found")

			payload, err := json.Marshal(accessToken)
			assert.Equal(t, err, nil, "Unexpected error")
			w.WriteHeader(http.StatusOK)
			w.Write(payload)
		}))
		defer tokenServer.Close()

		user := `{"user": "me", "groups": ["admin", "users"]}`
		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, req.Header.Get("Authorization"), "Bearer abcde")
			w.Header().Set("Content-Type", "application/json")

			assert.Equal(t, req.URL.RawQuery, "key=value&chiave=valore")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer resourceServer.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, resourceServer.URL+"?key=value&chiave=valore", nil)

		proxyConfig := entities.Proxy{
			Authentication:           "oauth2",
			ClientId:                 "6779ef20e75817b79602",
			ClientSecret:             "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl:           tokenServer.URL,
			TargetBaseUrl:            resourceServer.URL,
			GrantType:                "client_credentials",
			TokenIssuerValidationUrl: "issuervalidationtest.com/test",
			AuthType:                 "client_secret_basic",
		}

		env := config.EnvironmentVariables{AllowProxyOptimizer: true}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)
		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("200 proxy request with token refresh", func(t *testing.T) {
		expiredToken := auth.AccessToken{
			AccessToken: "expired",
			ExpiresIn:   json.RawMessage(`60`),
			Scope:       "write:users read:users",
			TokenType:   "bearer",
		}

		tokenServerInvocationCount := 0
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()

			if tokenServerInvocationCount == 0 {
				//mocking expired token response
				assert.Equal(t, req.Header.Get("Authorization"), "Bearer expired", "Unexpected auth header")
				w.WriteHeader(http.StatusUnauthorized)
				tokenServerInvocationCount++
				return
			}

			authHeader := "Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw=="
			assert.Equal(t, req.Header.Get("Content-Type"), "application/x-www-form-urlencoded", "Unexpected content type")
			assert.Equal(t, req.Header.Get("Authorization"), authHeader, "Unexpected auth header")

			requestBodyBytes, err := io.ReadAll(req.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			expectedBody := "grant_type=client_credentials"
			assert.Equal(t, string(requestBodyBytes), expectedBody, "Unexpected request body found")

			payload, err := json.Marshal(accessToken)
			assert.Equal(t, err, nil, "Unexpected error")
			assert.Equal(t, tokenServerInvocationCount, 1)
			w.WriteHeader(http.StatusOK)
			w.Write(payload)
		}))
		defer tokenServer.Close()

		user := `{"user": "me", "groups": ["admin", "users"]}`
		body := `{"test_id": "test_value"}`

		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			authHeader := req.Header.Get("Authorization")
			if authHeader == "Bearer expired" {
				t.Fail()
			}

			assert.Equal(t, authHeader, "Bearer abcde")

			requestBodyBytes, err := io.ReadAll(req.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			assert.Equal(t, string(requestBodyBytes), body, "Unexpected request body found")

			w.Header().Set("Content-Type", "application/json")

			_, err = w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer resourceServer.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodPost, resourceServer.URL, strings.NewReader(body))

		proxyConfig := entities.Proxy{
			Authentication:           "oauth2",
			ClientId:                 "6779ef20e75817b79602",
			ClientSecret:             "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl:           tokenServer.URL,
			TargetBaseUrl:            resourceServer.URL,
			TokenIssuerValidationUrl: fmt.Sprintf("%s/token-info", tokenServer.URL),
			GrantType:                "client_credentials",
			AuthType:                 "client_secret_basic",
		}

		env := config.EnvironmentVariables{AllowProxyOptimizer: true}

		tokensCache := auth.NewTokensCache(30)
		tokensCache.SetCachedToken(resourceServer.URL, expiredToken)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("401 failed to proxy request - token expiration unknown - token cache cleared", func(t *testing.T) {
		expiredToken := auth.AccessToken{
			AccessToken: "expired",
			ExpiresIn:   json.RawMessage(`0`),
			Scope:       "write:users read:users",
			TokenType:   "bearer",
		}

		tokenServerInvocationCount := 0
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()

			tokenServerInvocationCount++

			//mocking expired token response
			assert.Equal(t, req.Header.Get("Authorization"), "Bearer expired", "Unexpected auth header")
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer tokenServer.Close()

		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()

			assert.Equal(t, req.Header.Get("Authorization"), "Bearer expired", "Unexpected auth header")
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer resourceServer.Close()

		body := `{"test_id": "test_value"}`
		request := httptest.NewRequestWithContext(defaultContext, http.MethodPost, resourceServer.URL, strings.NewReader(body))
		recorder := httptest.NewRecorder()

		proxyConfig := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: tokenServer.URL,
			TargetBaseUrl:  resourceServer.URL,
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
		}

		env := config.EnvironmentVariables{AllowProxyOptimizer: true}

		tokensCache := auth.NewTokensCache(30)
		tokensCache.SetCachedToken(resourceServer.URL, expiredToken)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 401, "Wrong status code.")

		token, ok := tokensCache.GetCachedToken(resourceServer.URL)
		assert.Equal(t, token.AccessToken, "", "No token should be found")
		assert.Equal(t, ok, false, "No token should be found")
		assert.Equal(t, tokenServerInvocationCount, 0, "Token is not refreshed")
	})

	t.Run("403 failed to proxy request - token expiration unknown - token cache cleared", func(t *testing.T) {
		expiredToken := auth.AccessToken{
			AccessToken: "expired",
			ExpiresIn:   json.RawMessage(`0`),
			Scope:       "write:users read:users",
			TokenType:   "bearer",
		}

		tokenServerInvocationCount := 0
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()

			tokenServerInvocationCount++

			//mocking expired token response
			assert.Equal(t, req.Header.Get("Authorization"), "Bearer expired", "Unexpected auth header")
			w.WriteHeader(http.StatusForbidden)
		}))
		defer tokenServer.Close()

		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()

			assert.Equal(t, req.Header.Get("Authorization"), "Bearer expired", "Unexpected auth header")
			w.WriteHeader(http.StatusForbidden)
		}))
		defer resourceServer.Close()

		body := `{"test_id": "test_value"}`
		request := httptest.NewRequestWithContext(defaultContext, http.MethodPost, resourceServer.URL, strings.NewReader(body))
		recorder := httptest.NewRecorder()

		proxyConfig := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: tokenServer.URL,
			TargetBaseUrl:  resourceServer.URL,
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
		}

		env := config.EnvironmentVariables{AllowProxyOptimizer: true}

		tokensCache := auth.NewTokensCache(30)
		tokensCache.SetCachedToken(resourceServer.URL, expiredToken)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 403, "Wrong status code.")

		token, ok := tokensCache.GetCachedToken(resourceServer.URL)
		assert.Equal(t, token.AccessToken, "", "No token should be found")
		assert.Equal(t, ok, false, "No token should be found")
		assert.Equal(t, tokenServerInvocationCount, 0, "Token is not refreshed")
	})

	t.Run("200 proxy request with token refresh in case time greater than ExpiresAt", func(t *testing.T) {
		now := time.Now().UTC()
		expiredToken := auth.AccessToken{
			AccessToken: "expired",
			ExpiresIn:   json.RawMessage(`0`),
			Scope:       "write:users read:users",
			TokenType:   "bearer",
			ExpiresAt:   now.AddDate(0, 0, -1),
		}
		accessToken := auth.AccessToken{
			AccessToken: "abcde",
			ExpiresIn:   json.RawMessage(`3600`),
			Scope:       "write:users read:users",
			TokenType:   "bearer",
		}

		tokenServerInvocationCount := 0
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()

			tokenServerInvocationCount++

			authHeader := "Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw=="
			assert.Equal(t, req.Header.Get("Content-Type"), "application/x-www-form-urlencoded", "Unexpected content type")
			assert.Equal(t, req.Header.Get("Authorization"), authHeader, "Unexpected auth header")

			requestBodyBytes, err := io.ReadAll(req.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			expectedBody := "grant_type=client_credentials"
			assert.Equal(t, string(requestBodyBytes), expectedBody, "Unexpected request body found")

			payload, err := json.Marshal(accessToken)
			assert.Equal(t, err, nil, "Unexpected error")
			assert.Equal(t, tokenServerInvocationCount, 1)
			w.WriteHeader(http.StatusOK)
			w.Write(payload)
		}))
		defer tokenServer.Close()

		user := `{"user": "me", "groups": ["admin", "users"]}`
		body := `{"test_id": "test_value"}`

		resourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			authHeader := req.Header.Get("Authorization")
			if authHeader == "Bearer expired" {
				t.Fail()
			}

			assert.Equal(t, authHeader, "Bearer abcde")

			requestBodyBytes, err := io.ReadAll(req.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			assert.Equal(t, string(requestBodyBytes), body, "Unexpected request body found")

			w.Header().Set("Content-Type", "application/json")

			_, err = w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer resourceServer.Close()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodPost, resourceServer.URL, strings.NewReader(body))

		proxyConfig := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: tokenServer.URL,
			TargetBaseUrl:  resourceServer.URL,
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
		}

		env := config.EnvironmentVariables{AllowProxyOptimizer: true}

		tokensCache := auth.NewTokensCache(30)
		tokensCache.SetCachedToken(resourceServer.URL, expiredToken)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
		token, ok := tokensCache.GetCachedToken(proxyConfig.TargetBaseUrl)
		assert.Equal(t, ok, true, "Token must exist")
		assert.Equal(
			t,
			token.ExpiresAt.Round(time.Second).Sub(now.Add(time.Hour*1).Round(time.Second)) < 10,
			true,
			"Token expires one hour later - test with a tolerance of ten seconds",
		)
	})

	t.Run("3XX without following redirects", func(t *testing.T) {
		gock.DisableNetworking()
		defer gock.Off()

		testHost := "https://my-service"
		testRedirectHost := "http://unsafe-redirect/api"
		testApiPath := "/api"

		gock.
			New(testHost).
			Get(testApiPath).
			ReplyFunc(func(r *gock.Response) {
				r.SetHeader("location", testRedirectHost)
				r.Status(http.StatusPermanentRedirect)
			})

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, testHost, nil)

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  fmt.Sprintf("%s%s", testHost, testApiPath),
		}

		env := config.EnvironmentVariables{
			AllowProxyOptimizer: true,
		}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, http.StatusPermanentRedirect, "Wrong status code.")
		assert.Equal(t, gock.IsDone(), true)
	})

	t.Run("200 allowed Content-Type of the target service response", func(t *testing.T) {
		testCase := []struct {
			contentType            string
			disallowedContentTypes []string
		}{
			{contentType: "text/html"},
			{contentType: "Text/HTML"},
			{contentType: "text/html;charset=utf-8"},
			{contentType: "text/html;charset=UTF-8"},
			{contentType: "Text/HTML;Charset=utf-8"},
			{contentType: "text/html; charset=utf-8"},
			{contentType: "text/html; charset=ISO-8859-4"},
			{contentType: "application/javascript"},
			{contentType: "text/javascript"},
			{contentType: "application/json"},
			{contentType: "application/json", disallowedContentTypes: []string{"text/html", "text/javascript", "application/javascript"}},
		}

		testHost := "https://my-service"
		testApiPath := "/api"

		for i, testCase := range testCase {
			env := config.EnvironmentVariables{AllowProxyOptimizer: true}
			env.DisallowedResponseContentTypes = testCase.disallowedContentTypes

			t.Run(fmt.Sprintf("test case #%d - Content-Type: %s - disallowedContentTypes: %s", i+1, testCase.contentType, strings.Join(testCase.disallowedContentTypes, ", ")), func(t *testing.T) {

				defer gock.Off()

				gock.
					New(testHost).
					Get(testApiPath).
					ReplyFunc(func(r *gock.Response) {
						r.SetHeader("Content-Type", testCase.contentType)
						r.Status(http.StatusOK)
					})

				recorder := httptest.NewRecorder()
				request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, testHost, nil)

				proxyConfig := entities.Proxy{
					Authentication: "none",
					TargetBaseUrl:  fmt.Sprintf("%s%s", testHost, testApiPath),
				}

				tokensCache := auth.NewTokensCache(30)

				ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

				assert.Equal(t, recorder.Code, 200)
				assert.Equal(t, gock.IsDone(), true)
			})
		}
	})

	t.Run("500 disallowed Content-Type of the target service response", func(t *testing.T) {
		testCases := []struct {
			contentType string
		}{
			{contentType: "text/html"},
			{contentType: "Text/HTML"},
			{contentType: "text/html;charset=utf-8"},
			{contentType: "text/html;charset=UTF-8"},
			{contentType: "Text/HTML;Charset=utf-8"},
			{contentType: "text/html; charset=utf-8"},
			{contentType: "text/html; charset=ISO-8859-4"},
			{contentType: "application/javascript"},
			{contentType: "text/javascript"},
		}

		testHost := "https://my-service"
		testApiPath := "/api"

		disallowedContentTypes := []string{"text/html", "text/javascript", "application/javascript"}
		env := config.EnvironmentVariables{AllowProxyOptimizer: true, DisallowedResponseContentTypes: disallowedContentTypes}

		for i, testCase := range testCases {
			t.Run(fmt.Sprintf("test case #%d - Content-Type: %s - disallowedContentTypes: %s", i+1, testCase.contentType, strings.Join(disallowedContentTypes, ", ")), func(t *testing.T) {

				defer gock.Off()

				gock.
					New(testHost).
					Get(testApiPath).
					ReplyFunc(func(r *gock.Response) {
						r.SetHeader("Content-Type", testCase.contentType)
						r.Status(http.StatusOK)
					})

				recorder := httptest.NewRecorder()
				request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, testHost, nil)

				proxyConfig := entities.Proxy{
					Authentication: "none",
					TargetBaseUrl:  fmt.Sprintf("%s%s", testHost, testApiPath),
				}

				tokensCache := auth.NewTokensCache(30)

				ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

				assert.Equal(t, recorder.Code, 500)
				assert.Equal(t, recorder.Body.String(), `{"message":"Content-Type of the target service response not allowed"}`)
				assert.Equal(t, gock.IsDone(), true)
			})
		}
	})

	t.Run("500 on target url not allowed", func(t *testing.T) {
		env := config.EnvironmentVariables{
			AllowProxyOptimizer: true,
			AllowedProxyTargetURLs: []string{
				"https://apis.target.com",
			},
		}
		repo, err := allowedtargets_repository.FromENV(env)
		assert.NilError(t, err)
		context := allowedtargets_service.RegisterInstance(
			context.Background(),
			allowedtargets_service.New(repo),
		)
		defer gock.Off()

		gock.
			New("https://not-allowed-target.com").
			Get("/api").
			ReplyFunc(func(r *gock.Response) {
				r.Status(http.StatusOK)
			})

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(context, http.MethodGet, "/", nil)

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  "https://not-allowed-target.com/api",
		}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 500)
		assert.Equal(t, recorder.Body.String(), `specified target URL is not allowed`)
		assert.Equal(t, gock.IsDone(), false)
	})

	t.Run("200 on target url allowed", func(t *testing.T) {
		env := config.EnvironmentVariables{
			AllowProxyOptimizer: true,
			AllowedProxyTargetURLs: []string{
				"https://apis.target.com",
			},
		}
		repo, err := allowedtargets_repository.FromENV(env)
		assert.NilError(t, err)
		context := allowedtargets_service.RegisterInstance(
			context.Background(),
			allowedtargets_service.New(repo),
		)

		gock.
			New("https://apis.target.com").
			Get("/api").
			ReplyFunc(func(r *gock.Response) {
				r.Status(http.StatusOK)
			})
		defer gock.Off()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(context, http.MethodGet, "/api", nil)

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  "https://apis.target.com",
		}

		tokensCache := auth.NewTokensCache(30)

		ProxyHandler(&proxyConfig, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200)
		assert.Equal(t, gock.IsDone(), true)
	})
}

func TestDirector(t *testing.T) {
	t.Run("Testing Director func overwrite host", func(t *testing.T) {
		logger, _ := test.NewNullLogger()
		log := logrus.NewEntry(logger)
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "http://test.com", nil)
		request.Host = "firstHost"

		proxyConfig := entities.Proxy{
			Authentication:           "oauth2",
			ClientId:                 "6779ef20e75817b79602",
			ClientSecret:             "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl:           "http://test-token-issuer.com",
			TargetBaseUrl:            "http://testTokenBaseUrl.com",
			GrantType:                "client_credentials",
			TokenIssuerValidationUrl: "issuervalidationtest.com/test",
			AuthType:                 "client_secret_basic",
		}

		env := config.EnvironmentVariables{AllowProxyOptimizer: true}
		assert.Equal(t, request.Host, "firstHost")
		ProxyDirector(log, env, "", &proxyConfig)(request)
		assert.Equal(t, request.Host, "testTokenBaseUrl.com")
		assert.Equal(t, request.Header.Get("x-forwarded-for"), "")
	})

	t.Run("Testing Director func overwrite host and keep x-forwarded-for header", func(t *testing.T) {
		logger, _ := test.NewNullLogger()
		log := logrus.NewEntry(logger)
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "http://test.com", nil)
		request.Host = "firstHost"
		request.Header.Set("X-Forwarded-For", "127.0.0.1")

		proxyConfig := entities.Proxy{
			Authentication:           "oauth2",
			ClientId:                 "6779ef20e75817b79602",
			ClientSecret:             "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl:           "http://test-token-issuer.com",
			TargetBaseUrl:            "http://testTokenBaseUrl.com",
			GrantType:                "client_credentials",
			TokenIssuerValidationUrl: "issuervalidationtest.com/test",
			AuthType:                 "client_secret_basic",
			HeadersToProxy:           []string{"x-forwarded-for"},
		}

		env := config.EnvironmentVariables{AllowProxyOptimizer: true}
		assert.Equal(t, request.Host, "firstHost")
		ProxyDirector(log, env, "", &proxyConfig)(request)
		assert.Equal(t, request.Host, "testTokenBaseUrl.com")
		assert.Equal(t, request.Header.Get("x-forwarded-for"), "127.0.0.1")
	})
}

func TestDynamicProxyHandler(t *testing.T) {
	t.Run("200 proxy cache is NOT expired, proxy request", func(t *testing.T) {
		proxyResponse := `"something"`
		externalService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			assert.Equal(t, req.URL.String(), "/feature")
			_, err := w.Write([]byte(proxyResponse))
			assert.Assert(t, err, nil)
		}))
		defer externalService.Close()

		proxiesCache := proxyservice.ProxyCache{
			"/external-service": {
				Expiration: 9661336238,
				Proxy: entities.Proxy{
					Authentication: "none",
					TargetBaseUrl:  externalService.URL,
				},
			},
		}
		env := config.EnvironmentVariables{ServiceConfigUrl: "/crud"}
		tokensCache := auth.NewTokensCache(30)

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "/external-service/feature", nil)

		DynamicProxyHandler(&proxiesCache, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), proxyResponse, "Wrong response body.")
	})

	t.Run("200 proxy cache is expired, fetch config and proxy request", func(t *testing.T) {
		proxyResponse := `"something"`
		externalService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			assert.Equal(t, req.URL.String(), "/feature")
			_, err := w.Write([]byte(proxyResponse))
			assert.Assert(t, err, nil)
		}))
		defer externalService.Close()

		isCrudCalled := false
		crud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			isCrudCalled = true

			assert.Equal(t, req.URL.Query().Get("basePath"), "/external-service", "Unexpected query")
			_, err := w.Write([]byte(fmt.Sprintf(`[{"creatorId":"public","targetBaseUrl":"%s","basePath":"/external-service"}]`, externalService.URL)))
			assert.Assert(t, err, nil)
		}))
		defer crud.Close()

		proxiesCache := proxyservice.ProxyCache{
			"/external-service": {
				Expiration: 0,
				Proxy:      entities.Proxy{},
			},
		}
		env := config.EnvironmentVariables{
			ServiceConfigUrl: crud.URL,
		}
		tokensCache := auth.NewTokensCache(30)

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "/external-service/feature", nil)

		DynamicProxyHandler(&proxiesCache, env, tokensCache)(recorder, request)

		assert.Equal(t, isCrudCalled, true, "Crud was not called")
		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), proxyResponse, "Wrong response body.")
	})

	t.Run("200 new proxy, fetch config and proxy request", func(t *testing.T) {
		proxyResponse := `"something"`
		externalService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			assert.Equal(t, req.URL.String(), "/feature")
			_, err := w.Write([]byte(proxyResponse))
			assert.Assert(t, err, nil)
		}))
		defer externalService.Close()

		crud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			assert.Equal(t, req.URL.Query().Get("basePath"), "/external-service", "Unexpected query")
			_, err := w.Write([]byte(fmt.Sprintf(`[{"creatorId":"public","targetBaseUrl":"%s","basePath":"/external-service"}]`, externalService.URL)))
			assert.Assert(t, err, nil)
		}))
		defer crud.Close()

		proxiesCache := proxyservice.ProxyCache{}
		env := config.EnvironmentVariables{
			ServiceConfigUrl: crud.URL,
		}
		tokensCache := auth.NewTokensCache(30)

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "/external-service/feature", nil)

		DynamicProxyHandler(&proxiesCache, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), proxyResponse, "Wrong response body.")
	})

	t.Run("500 unknown base path", func(t *testing.T) {
		crud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(`[]`))
			assert.Assert(t, err, nil)
		}))
		defer crud.Close()

		proxiesCache := proxyservice.ProxyCache{}
		env := config.EnvironmentVariables{
			ServiceConfigUrl: crud.URL,
		}
		tokensCache := auth.NewTokensCache(30)

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "/unknown/path", nil)

		DynamicProxyHandler(&proxiesCache, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 500, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), "proxy not found", "Wrong response body.")
	})

	t.Run("500 fetched proxy does not respect json schema", func(t *testing.T) {
		crud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(`[{"creatorId":"public","basePath":"/external-service"}]`))
			assert.Assert(t, err, nil)
		}))
		defer crud.Close()

		proxiesCache := proxyservice.ProxyCache{}
		env := config.EnvironmentVariables{
			ServiceConfigUrl: crud.URL,
		}
		tokensCache := auth.NewTokensCache(30)

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "/unknown/path", nil)

		DynamicProxyHandler(&proxiesCache, env, tokensCache)(recorder, request)

		assert.Equal(t, recorder.Code, 500, "Wrong status code.")
		assert.Assert(t, strings.Contains(recorder.Body.String(), "targetBaseUrl"), "Wrong response body.")
	})
}

func TestUnitaryFunctions(t *testing.T) {
	t.Run("retrieveUrl returns correct result without path parameters - call exactly the basePath", func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())
		env := config.EnvironmentVariables{AllowProxyOptimizer: true}
		proxyConfig := entities.Proxy{
			TargetBaseUrl: "https://docs.mia-platform.eu/docs",
			BasePath:      "/docs",
		}
		startingConfig := proxyConfig
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "https://mia-platform.eu/docs", nil)
		destinationUrl := retrieveUrl(logger, env, &proxyConfig, request)

		assert.Equal(t, destinationUrl, "https://docs.mia-platform.eu/docs", "Wrong destination url.")
		assert.Assert(t, reflect.DeepEqual(startingConfig, proxyConfig), "Configuration is changed.")
	})

	t.Run("retrieveUrl returns correct result without path parameters - add path after basePath", func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())
		env := config.EnvironmentVariables{AllowProxyOptimizer: true}
		proxyConfig := entities.Proxy{
			TargetBaseUrl: "https://docs.mia-platform.eu/docs",
			BasePath:      "/docs",
		}
		startingConfig := proxyConfig
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "https://mia-platform.eu/docs/fast_data", nil)
		destinationUrl := retrieveUrl(logger, env, &proxyConfig, request)

		assert.Equal(t, destinationUrl, "https://docs.mia-platform.eu/docs/fast_data", "Wrong destination url.")
		assert.Assert(t, reflect.DeepEqual(startingConfig, proxyConfig), "Configuration is changed.")
	})

	t.Run("retrieveUrl returns correct result without path parameters and service prefix", func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())
		env := config.EnvironmentVariables{AllowProxyOptimizer: true, ServicePrefix: "/service-prefix"}
		proxyConfig := entities.Proxy{
			TargetBaseUrl: "https://docs.mia-platform.eu/docs",
			BasePath:      "/docs/fast_data",
		}
		startingConfig := proxyConfig
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "https://mia-platform.eu/service-prefix/docs/fast_data/feature", nil)
		destinationUrl := retrieveUrl(logger, env, &proxyConfig, request)

		assert.Equal(t, destinationUrl, "https://docs.mia-platform.eu/docs/feature", "Wrong destination url.")
		assert.Assert(t, reflect.DeepEqual(startingConfig, proxyConfig), "Configuration is changed.")
	})

	t.Run("retrieveUrl returns correct result with path parameter and two-level basePath", func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())
		env := config.EnvironmentVariables{AllowProxyOptimizer: true}
		proxyConfig := entities.Proxy{
			TargetBaseUrl: "https://docs.mia-platform.eu/docs/{pageId}",
			BasePath:      "/docs/{pageId}",
		}
		startingConfig := proxyConfig
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "https://mia-platform.eu/docs/fast_data", nil)
		destinationUrl := retrieveUrl(logger, env, &proxyConfig, request)

		assert.Equal(t, destinationUrl, "https://docs.mia-platform.eu/docs/fast_data", "Wrong destination url.")
		assert.Assert(t, reflect.DeepEqual(startingConfig, proxyConfig), "Configuration is changed.")
	})

	t.Run("retrieveUrl returns correct result with path parameter as basePath", func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())
		env := config.EnvironmentVariables{AllowProxyOptimizer: true}
		proxyConfig := entities.Proxy{
			TargetBaseUrl: "https://docs.mia-platform.eu/{pageId}",
			BasePath:      "/{pageId}",
		}
		startingConfig := proxyConfig
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "https://mia-platform.eu/docs/fast_data", nil)
		destinationUrl := retrieveUrl(logger, env, &proxyConfig, request)

		assert.Equal(t, destinationUrl, "https://docs.mia-platform.eu/docs/fast_data", "Wrong destination url.")
		assert.Assert(t, reflect.DeepEqual(startingConfig, proxyConfig), "Configuration is changed.")
	})

	t.Run("retrieveUrl returns correct result with path parameter as basePath and path parameter in the middle of targetBaseUrl", func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())
		env := config.EnvironmentVariables{AllowProxyOptimizer: true}
		proxyConfig := entities.Proxy{
			TargetBaseUrl: "https://docs.mia-platform.eu/{pageId}/test",
			BasePath:      "/{pageId}",
		}
		startingConfig := proxyConfig
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "https://mia-platform.eu/docs/fast_data", nil)
		destinationUrl := retrieveUrl(logger, env, &proxyConfig, request)

		assert.Equal(t, destinationUrl, "https://docs.mia-platform.eu/docs/test/fast_data", "Wrong destination url.")
		assert.Assert(t, reflect.DeepEqual(startingConfig, proxyConfig), "Configuration is changed.")
	})

	t.Run("retrieveUrl returns correct result with path parameter and two-level basePath and service prefix with slash", func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())
		env := config.EnvironmentVariables{AllowProxyOptimizer: true, ServicePrefix: "/service-prefix"}
		proxyConfig := entities.Proxy{
			TargetBaseUrl: "https://docs.mia-platform.eu/docs/{firstParam}/{secondParam}",
			BasePath:      "/docs/{secondParam}/{firstParam}",
		}
		startingConfig := proxyConfig
		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, "https://mia-platform.eu/service-prefix/docs/second/first/additionalParam", nil)
		destinationUrl := retrieveUrl(logger, env, &proxyConfig, request)

		assert.Equal(t, destinationUrl, "https://docs.mia-platform.eu/docs/first/second/additionalParam", "Wrong destination url.")
		assert.Assert(t, reflect.DeepEqual(startingConfig, proxyConfig), "Configuration is changed.")
	})

	t.Run("getRedactedHeaders redact default headers without modifying source headers", func(t *testing.T) {
		env := config.EnvironmentVariables{}
		source := http.Header{
			"Authorization":       []string{"s3cr3t"},
			"Cookie":              []string{"sup3r-s3cr3t", "p4ssw0rd"},
			"Proxy-Authorization": []string{"another-secret"},
			"Set-Cookie":          []string{"secret-cookie1", "secret-cookie2", "secret-cookie3"},
			"Www-Authenticate":    []string{"authentication-token"},
			"My-Api-Key":          []string{"api-key-value"},
			"My-Secret-Header":    []string{"custom-s3cr3t"},
			"Generic":             []string{"something"},
		}
		result := getRedactedHeaders(env, source)

		assert.DeepEqual(t, result, http.Header{
			"Authorization":       []string{"[REDACTED]"},
			"Cookie":              []string{"[REDACTED]"},
			"Proxy-Authorization": []string{"[REDACTED]"},
			"Set-Cookie":          []string{"[REDACTED]"},
			"Www-Authenticate":    []string{"[REDACTED]"},
			"My-Api-Key":          []string{"api-key-value"},
			"My-Secret-Header":    []string{"custom-s3cr3t"},
			"Generic":             []string{"something"},
		})
		assert.DeepEqual(t, source, http.Header{
			"Authorization":       []string{"s3cr3t"},
			"Cookie":              []string{"sup3r-s3cr3t", "p4ssw0rd"},
			"Proxy-Authorization": []string{"another-secret"},
			"Set-Cookie":          []string{"secret-cookie1", "secret-cookie2", "secret-cookie3"},
			"Www-Authenticate":    []string{"authentication-token"},
			"My-Api-Key":          []string{"api-key-value"},
			"My-Secret-Header":    []string{"custom-s3cr3t"},
			"Generic":             []string{"something"},
		})
	})

	t.Run("getRedactedHeaders redact default and additional headers without modifying source headers", func(t *testing.T) {
		env := config.EnvironmentVariables{AdditionalHeadersToRedact: []string{"My-Api-Key", "My-Secret-Header"}}
		source := http.Header{
			"Authorization":       []string{"s3cr3t"},
			"Cookie":              []string{"sup3r-s3cr3t", "p4ssw0rd"},
			"Proxy-Authorization": []string{"another-secret"},
			"Set-Cookie":          []string{"secret-cookie1", "secret-cookie2", "secret-cookie3"},
			"Www-Authenticate":    []string{"authentication-token"},
			"My-Api-Key":          []string{"api-key-value"},
			"My-Secret-Header":    []string{"custom-s3cr3t"},
			"Generic":             []string{"something"},
		}
		result := getRedactedHeaders(env, source)

		assert.DeepEqual(t, result, http.Header{
			"Authorization":       []string{"[REDACTED]"},
			"Cookie":              []string{"[REDACTED]"},
			"Proxy-Authorization": []string{"[REDACTED]"},
			"Set-Cookie":          []string{"[REDACTED]"},
			"Www-Authenticate":    []string{"[REDACTED]"},
			"My-Api-Key":          []string{"[REDACTED]"},
			"My-Secret-Header":    []string{"[REDACTED]"},
			"Generic":             []string{"something"},
		})
		assert.DeepEqual(t, source, http.Header{
			"Authorization":       []string{"s3cr3t"},
			"Cookie":              []string{"sup3r-s3cr3t", "p4ssw0rd"},
			"Proxy-Authorization": []string{"another-secret"},
			"Set-Cookie":          []string{"secret-cookie1", "secret-cookie2", "secret-cookie3"},
			"Www-Authenticate":    []string{"authentication-token"},
			"My-Api-Key":          []string{"api-key-value"},
			"My-Secret-Header":    []string{"custom-s3cr3t"},
			"Generic":             []string{"something"},
		})
	})

	t.Run("checkContentTypeHeader return error with disallowed Content-Type", func(t *testing.T) {
		disallowedContentType := "content-type-to-block"
		env := config.EnvironmentVariables{DisallowedResponseContentTypes: []string{disallowedContentType}}
		headers := http.Header{
			"Content-Type": []string{disallowedContentType},
		}
		err := checkContentTypeHeader(env, headers)

		assert.Error(t, err, fmt.Sprintf("Content-Type header with value %v not accepted", disallowedContentType))
	})

	t.Run("checkContentTypeHeader return error with a value that contains disallowed Content-Type", func(t *testing.T) {
		disallowedContentType := "content-type-to-block"
		env := config.EnvironmentVariables{DisallowedResponseContentTypes: []string{disallowedContentType}}
		conentTypeHeader := fmt.Sprintf("%v ;some-encoding", disallowedContentType)
		headers := http.Header{
			"Content-Type": []string{conentTypeHeader},
		}
		err := checkContentTypeHeader(env, headers)

		assert.Error(t, err, fmt.Sprintf("Content-Type header with value %v not accepted", conentTypeHeader))
	})

	t.Run("checkContentTypeHeader does not return error with correct Content-Type", func(t *testing.T) {
		disallowedContentType := "content-type-to-block"
		env := config.EnvironmentVariables{DisallowedResponseContentTypes: []string{disallowedContentType}}
		headers := http.Header{
			"Content-Type": []string{"correct-content-type"},
		}
		err := checkContentTypeHeader(env, headers)

		assert.Equal(t, err, nil)
	})
}

func TestBasePathExtractor(t *testing.T) {
	prefixes := []string{
		"/the-base-path",
		"/extensions/:",
		"/extensions/:/something-else-that-is-prefix",
		"/extensions/something-else-again",
		"/pippo/something-else-that-is-prefix",
	}

	graph := pathextractor.CreateBasePathExtractorGraph(prefixes)

	testCases := []struct {
		requestPath      string
		expectedBasePath string
	}{
		{
			requestPath:      "/the-base-path/some/api",
			expectedBasePath: "/the-base-path",
		},
		{
			requestPath:      "/the-base-path/some/api",
			expectedBasePath: "/the-base-path",
		},
		{
			requestPath:      "/extensions/123123/some/api",
			expectedBasePath: "/extensions/123123",
		},
		{
			requestPath:      "/extensions/123123/something-else-that-is-prefix/some/api",
			expectedBasePath: "/extensions/123123/something-else-that-is-prefix",
		},
		{
			requestPath:      "/pippo/something-else-that-is-prefix/some/api",
			expectedBasePath: "/pippo/something-else-that-is-prefix",
		},
	}
	for i, test := range testCases {
		t.Run(fmt.Sprintf("test case #%d %s -> %s", i+1, test.requestPath, test.expectedBasePath), func(t *testing.T) {
			result := extractBasePath(test.requestPath, graph)
			assert.Equal(t, result, test.expectedBasePath, "Wrong base path foudn.")
		})
	}
}

func TestHeaders_Integration(t *testing.T) {
	t.Run("default all headers are proxied", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// verify that all the original request headers were forwarded
			assert.Equal(t, req.Header.Get("Content-Type"), "application/json")
			assert.Equal(t, req.Header.Get("Accept"), "*/*")
			assert.Equal(t, req.Header.Get("X-Real-IP"), "1.1.1.1")
			assert.Equal(t, req.Header.Get("X-Custom-Header"), "my-custom-header")

			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()
		recorder := httptest.NewRecorder()

		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL, nil)
		request.Header.Set("Accept", "*/*")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Real-IP", "1.1.1.1")
		request.Header.Set("X-Custom-Header", "my-custom-header")

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  s.URL,
		}

		env := config.EnvironmentVariables{}

		ProxyHandler(&proxyConfig, env, nil)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("additionalHeaders are appended", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// verify that all the original request headers were forwarded
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			assert.Equal(t, "*/*", req.Header.Get("Accept"))
			assert.Equal(t, "1.1.1.1", req.Header.Get("X-Real-IP"))
			assert.Equal(t, "my-custom-header", req.Header.Get("X-Custom-Header"))
			assert.Equal(t, "123", req.Header.Get("Custom-Additional-Header"))

			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()
		recorder := httptest.NewRecorder()

		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL, nil)
		request.Header.Set("Accept", "*/*")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Real-IP", "1.1.1.1")
		request.Header.Set("X-Custom-Header", "my-custom-header")

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  s.URL,
			AdditionalHeaders: []entities.AdditionalHeader{
				{
					Name:  "Custom-Additional-Header",
					Value: "123",
				},
			},
		}

		env := config.EnvironmentVariables{}

		ProxyHandler(&proxyConfig, env, nil)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("only HeadersToProxy are forwarded", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// verify that all the original request headers were forwarded
			assert.Equal(t, "", req.Header.Get("Accept"))
			assert.Equal(t, "", req.Header.Get("Content-Type"))
			assert.Equal(t, "", req.Header.Get("X-Real-IP"))
			assert.Equal(t, "my-custom-header", req.Header.Get("X-Custom-Header"))

			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()
		recorder := httptest.NewRecorder()

		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL, nil)
		request.Header.Set("Accept", "*/*")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Real-IP", "1.1.1.1")
		request.Header.Set("X-Custom-Header", "my-custom-header")

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  s.URL,
			HeadersToProxy: []string{"X-Custom-Header"},
		}

		env := config.EnvironmentVariables{}

		ProxyHandler(&proxyConfig, env, nil)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("HeaderBlockList are not forwared", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// verify that all the original request headers were forwarded
			assert.Equal(t, "*/*", req.Header.Get("Accept"))
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			assert.Equal(t, "", req.Header.Get("X-Real-IP"))
			assert.Equal(t, "", req.Header.Get("X-Custom-Header"))

			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()
		recorder := httptest.NewRecorder()

		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL, nil)
		request.Header.Set("Accept", "*/*")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Real-IP", "1.1.1.1")
		request.Header.Set("X-Custom-Header", "my-custom-header")

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  s.URL,
		}

		env := config.EnvironmentVariables{
			HeaderBlockList: []string{"X-Real-IP", "X-Custom-Header"},
		}

		ProxyHandler(&proxyConfig, env, nil)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})

	t.Run("HeadersToRemap are remapped correctly", func(t *testing.T) {
		user := `{"user": "me", "groups": ["admin", "users"]}`
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// verify that all the original request headers were forwarded
			assert.Equal(t, "*/*", req.Header.Get("Accept"))
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			assert.Equal(t, "", req.Header.Get("X-To-Remap"))
			assert.Equal(t, "remapped header", req.Header.Get("Remapped-Header"))
			assert.Equal(t, "", req.Header.Get("X-Remapped-To-Block"))
			assert.Equal(t, "", req.Header.Get("X-Header-To-Block"))

			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(user))
			assert.Assert(t, err, nil)
		}))
		defer s.Close()
		recorder := httptest.NewRecorder()

		request := httptest.NewRequestWithContext(defaultContext, http.MethodGet, s.URL, nil)
		request.Header.Set("Accept", "*/*")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-To-Remap", "remapped header")
		request.Header.Set("X-Remapped-To-Block", "my-custom-header")

		proxyConfig := entities.Proxy{
			Authentication: "none",
			TargetBaseUrl:  s.URL,
		}

		env := config.EnvironmentVariables{
			HeadersToRemap: map[string]string{
				"X-To-Remap":          "Remapped-Header",
				"X-Remapped-To-Block": "X-Header-To-Block",
			},
			HeaderBlockList: []string{"X-Header-To-Block"},
		}

		ProxyHandler(&proxyConfig, env, nil)(recorder, request)

		assert.Equal(t, recorder.Code, 200, "Wrong status code.")
		assert.Equal(t, recorder.Body.String(), user, "Wrong response body.")
	})
}
