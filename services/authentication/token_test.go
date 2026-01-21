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

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"proxy-manager/entities"

	glogrus "github.com/mia-platform/glogger/v4/loggers/logrus"
	"gotest.tools/assert"
)

func TestGetAccessToken(t *testing.T) {
	t.Run(`Access token as JSON with expiresIn as int is properly obtained (grant_type=client_credentials)`, func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())
		accessTokenAsJSON := `{"access_token":"abcde","expires_in":60,"scope":"write:users read:users","token_type":"bearer"}`

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()

			assert.Equal(
				t,
				r.Header.Get("Content-Type"),
				"application/x-www-form-urlencoded",
				"Unexpected content type",
			)
			assert.Equal(
				t,
				r.Header.Get("Authorization"),
				"Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw==",
				"Authorization must be provided",
			)

			assert.Equal(t, r.PostFormValue("grant_type"), "client_credentials")

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(accessTokenAsJSON))
		}))

		config := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: server.URL,
			TargetBaseUrl:  "external-service.com",
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
		}

		tokensCache := NewTokensCache(30)

		obtainedToken, err := tokensCache.GetAccessToken(logger, &config)
		assert.NilError(t, err, "Unexpected error")
		assert.Equal(t, obtainedToken, "abcde", "Unexpected value")
		assert.Equal(t, obtainedToken, "abcde", "Unexpected value")
	})

	t.Run(`Access token as JSON with expiresIn as string is properly obtained (grant_type=client_credentials)`, func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())
		accessTokenAsJSON := `{"access_token":"abcde","expires_in":"60","scope":"write:users read:users","token_type":"bearer"}`

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()

			assert.Equal(
				t,
				r.Header.Get("Content-Type"),
				"application/x-www-form-urlencoded",
				"Unexpected content type",
			)
			assert.Equal(
				t,
				r.Header.Get("Authorization"),
				"Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw==",
				"Authorization must be provided",
			)

			assert.Equal(t, r.PostFormValue("grant_type"), "client_credentials")

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(accessTokenAsJSON))
		}))

		config := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: server.URL,
			TargetBaseUrl:  "external-service.com",
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
		}

		tokensCache := NewTokensCache(30)

		obtainedToken, err := tokensCache.GetAccessToken(logger, &config)
		assert.NilError(t, err, "Unexpected error")
		assert.Equal(t, obtainedToken, "abcde", "Unexpected value")
	})

	t.Run(`Failed to get access token with expiresIn as invalid string (grant_type=client_credentials)`, func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())
		accessTokenAsJSON := `{"access_token":"abcde","expires_in":"invalidString","scope":"write:users read:users","token_type":"bearer"}`

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()

			assert.Equal(
				t,
				r.Header.Get("Content-Type"),
				"application/x-www-form-urlencoded",
				"Unexpected content type",
			)
			assert.Equal(
				t,
				r.Header.Get("Authorization"),
				"Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw==",
				"Authorization must be provided",
			)

			assert.Equal(t, r.PostFormValue("grant_type"), "client_credentials")

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(accessTokenAsJSON))
		}))

		config := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: server.URL,
			TargetBaseUrl:  "external-service.com",
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
		}

		tokensCache := NewTokensCache(30)

		_, err := tokensCache.GetAccessToken(logger, &config)
		assert.Error(t, err, "failed to convert expires_in from string to int: strconv.Atoi: parsing \"invalidString\": invalid syntax")
	})

	t.Run(`Access token is properly obtained (grant_type=client_credentials)`, func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())

		accessToken := AccessToken{
			AccessToken: "abcde",
			ExpiresIn:   json.RawMessage(`60`),
			Scope:       "write:users read:users",
			TokenType:   "bearer",
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()

			assert.Equal(
				t,
				r.Header.Get("Content-Type"),
				"application/x-www-form-urlencoded",
				"Unexpected content type",
			)
			assert.Equal(
				t,
				r.Header.Get("Authorization"),
				"Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw==",
				"Authorization must be provided",
			)

			assert.Equal(t, r.PostFormValue("grant_type"), "client_credentials")

			payload, err := json.Marshal(accessToken)
			assert.NilError(t, err, "Unexpected error")
			w.WriteHeader(http.StatusOK)
			w.Write(payload)
		}))

		config := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: server.URL,
			TargetBaseUrl:  "external-service.com",
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
		}

		tokensCache := NewTokensCache(30)

		obtainedToken, err := tokensCache.GetAccessToken(logger, &config)
		assert.NilError(t, err, "Unexpected error")
		assert.Equal(t, obtainedToken, "abcde", "Unexpected value")
	})

	t.Run(`Access token is properly obtained (grant_type=client_credentials + audience)`, func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())

		config := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TargetBaseUrl:  "external-service.com",
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
			AdditionalAuthFields: map[string]string{
				"audience":        "dih",
				"otherCustomProp": "randomValue",
			},
		}

		accessToken := AccessToken{
			AccessToken: "abcde",
			ExpiresIn:   json.RawMessage(`60`),
			Scope:       "write:users read:users",
			TokenType:   "bearer",
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()

			assert.Equal(
				t,
				r.Header.Get("Content-Type"),
				"application/x-www-form-urlencoded",
				"Unexpected content type",
			)

			assert.Equal(t, r.PostFormValue("grant_type"), config.GrantType)
			assert.Equal(t, r.PostFormValue("audience"), config.AdditionalAuthFields["audience"])
			assert.Equal(t, r.PostFormValue("otherCustomProp"), config.AdditionalAuthFields["otherCustomProp"])

			assert.Equal(
				t,
				r.Header.Get("Authorization"),
				"Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw==",
				"Authorization must be provided",
			)

			assert.Equal(t, r.PostFormValue("grant_type"), "client_credentials")

			payload, err := json.Marshal(accessToken)
			assert.NilError(t, err, "Unexpected error")
			w.WriteHeader(http.StatusOK)
			w.Write(payload)
		}))
		config.TokenIssuerUrl = server.URL

		tokensCache := NewTokensCache(30)

		obtainedToken, err := tokensCache.GetAccessToken(logger, &config)
		assert.NilError(t, err, "Unexpected error")
		assert.Equal(t, obtainedToken, "abcde", "Unexpected value")
	})

	t.Run(`Access token is properly validated`, func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())

		accessToken := AccessToken{
			AccessToken: "abcde",
			ExpiresIn:   json.RawMessage(`60`),
			Scope:       "write:users read:users",
			TokenType:   "bearer",
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			assert.Equal(t, r.RequestURI, "/token-info")
			assert.Equal(t, r.Header["Authorization"][0], "Bearer abcde")

			w.WriteHeader(http.StatusOK)
		}))

		config := entities.Proxy{
			Authentication:           "oauth2",
			ClientId:                 "6779ef20e75817b79602",
			ClientSecret:             "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl:           server.URL,
			TokenIssuerValidationUrl: fmt.Sprintf("%s/token-info", server.URL),
			TargetBaseUrl:            "external-service.com",
			GrantType:                "client_credentials",
			AuthType:                 "client_secret_basic",
		}

		tokensCache := NewTokensCache(30)
		obtainedToken, err := tokensCache.validateCachedToken(accessToken, logger, &config)
		assert.NilError(t, err, "Unexpected error")
		assert.Equal(t, obtainedToken, true, "Unexpected value")
	})

	t.Run(`Access token validation return false if validator throws error`, func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())

		accessToken := AccessToken{
			AccessToken: "abcde",
			ExpiresIn:   json.RawMessage(`60`),
			Scope:       "write:users read:users",
			TokenType:   "bearer",
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()

			w.WriteHeader(http.StatusInternalServerError)
		}))

		config := entities.Proxy{
			Authentication:           "oauth2",
			ClientId:                 "6779ef20e75817b79602",
			ClientSecret:             "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl:           server.URL,
			TokenIssuerValidationUrl: fmt.Sprintf("%s/token-info", server.URL),
			TargetBaseUrl:            "external-service.com",
			GrantType:                "client_credentials",
			AuthType:                 "client_secret_basic",
		}

		tokensCache := NewTokensCache(30)
		response, _ := tokensCache.validateCachedToken(accessToken, logger, &config)
		assert.Equal(t, response, false)
	})

	t.Run(`Access token is properly obtained (grant_type=password)`, func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())

		config := entities.Proxy{
			Authentication: "oauth2",
			Username:       "username",
			Password:       "pwd",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TargetBaseUrl:  "external-service.com",
			GrantType:      "password",
		}

		accessToken := AccessToken{
			AccessToken: "abcde",
			ExpiresIn:   json.RawMessage(`60`),
			Scope:       "write:users read:users",
			TokenType:   "bearer",
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()

			assert.Equal(
				t,
				r.Header.Get("Content-Type"),
				"application/x-www-form-urlencoded",
				"Unexpected content type",
			)
			assert.Equal(t, r.Header.Get("Authorization"), "", "No authorization should be provided")

			assert.Equal(t, r.PostFormValue("grant_type"), config.GrantType)
			assert.Equal(t, r.PostFormValue("username"), config.Username)
			assert.Equal(t, r.PostFormValue("password"), config.Password)
			assert.Equal(t, r.PostFormValue("client_id"), config.ClientId)
			assert.Equal(t, r.PostFormValue("client_secret"), config.ClientSecret)

			payload, err := json.Marshal(accessToken)
			assert.NilError(t, err, "Unexpected error")
			w.WriteHeader(http.StatusOK)
			w.Write(payload)
		}))
		config.TokenIssuerUrl = server.URL

		tokensCache := NewTokensCache(30)

		obtainedToken, err := tokensCache.GetAccessToken(logger, &config)
		assert.NilError(t, err, "Unexpected error")
		assert.Equal(t, obtainedToken, "abcde", "Unexpected value")
	})

	t.Run(`Cached access token is properly obtained`, func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())

		config := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: "issuer.com",
			TargetBaseUrl:  "external-service.com",
			GrantType:      "client_credentials",
		}

		accessToken := AccessToken{
			AccessToken: "abcde",
			ExpiresIn:   json.RawMessage(`60`),
			Scope:       "write:users read:users",
			TokenType:   "bearer",
		}
		tokensCache := NewTokensCache(30)
		tokensCache.SetCachedToken(config.TargetBaseUrl, accessToken)

		obtainedToken, err := tokensCache.GetAccessToken(logger, &config)
		assert.Equal(t, err, nil, "Unexpected error")
		assert.Equal(t, obtainedToken, "abcde", "Unexpected value")
	})

	t.Run(`500 Failed to get access token for token issuer internal error`, func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()

			assert.Equal(t, r.Header.Get("Content-Type"), "application/x-www-form-urlencoded", "Unexpected content type")
			assert.Equal(t, r.Header.Get("Authorization"), "Basic Njc3OWVmMjBlNzU4MTdiNzk2MDI6R0JBeWZWTDdZV3RQNmd1ZExJamJSWlZfTjBkVw==", "Unexpected content type")

			requestBodyBytes, err := io.ReadAll(r.Body)
			assert.Equal(t, err, nil, "Unexpected error")

			expectedBody := "grant_type=client_credentials"

			assert.Equal(t, string(requestBodyBytes), expectedBody, "Unexpected request body found")

			w.WriteHeader(http.StatusInternalServerError)
		}))

		config := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: server.URL,
			TargetBaseUrl:  "external-service.com",
			GrantType:      "client_credentials",
			AuthType:       "client_secret_basic",
		}

		tokensCache := NewTokensCache(30)

		obtainedToken, err := tokensCache.GetAccessToken(logger, &config)
		assert.Equal(t, err.Error(), "unexpected status code on token request: 500", "Unexpected error")
		assert.Equal(t, obtainedToken, "", "Unexpected value")
	})

	t.Run(`Cached access token is properly deleted`, func(t *testing.T) {
		logger := glogrus.FromContext(context.Background())

		config := entities.Proxy{
			Authentication: "oauth2",
			ClientId:       "6779ef20e75817b79602",
			ClientSecret:   "GBAyfVL7YWtP6gudLIjbRZV_N0dW",
			TokenIssuerUrl: "issuer.com",
			TargetBaseUrl:  "external-service.com",
			GrantType:      "client_credentials",
		}

		accessToken := AccessToken{
			AccessToken: "abcde",
			ExpiresIn:   json.RawMessage(`60`),
			Scope:       "write:users read:users",
			TokenType:   "bearer",
		}
		tokensCache := NewTokensCache(30)
		tokensCache.SetCachedToken(config.TargetBaseUrl, accessToken)

		obtainedToken, err := tokensCache.GetAccessToken(logger, &config)
		assert.Equal(t, err, nil, "Unexpected error")
		assert.Equal(t, obtainedToken, "abcde", "Unexpected value")

		tokensCache.DeleteCachedToken(config.TargetBaseUrl)
		_, ok := tokensCache.GetCachedToken(config.TargetBaseUrl)
		assert.Equal(t, ok, false, "Expected empty cache")
	})
}

func TestTokenExpiryBuffer(t *testing.T) {
	tokensCache := NewTokensCache(30) // Use the default 30-second buffer

	t.Run("Token is considered expired with buffer before actual expiration", func(t *testing.T) {
		token := AccessToken{
			AccessToken: "test-token",
			ExpiresIn:   json.RawMessage(`20`),
			ExpiresAt:   time.Now().UTC().Add(20 * time.Second),
		}

		assert.Equal(t, tokensCache.isTokenExpired(&token), true, "Token should be considered expired due to buffer")
	})

	t.Run("Token is not considered expired when beyond buffer threshold", func(t *testing.T) {
		token := AccessToken{
			AccessToken: "test-token",
			ExpiresIn:   json.RawMessage(`60`),
			ExpiresAt:   time.Now().UTC().Add(60 * time.Second),
		}

		assert.Equal(t, tokensCache.isTokenExpired(&token), false, "Token should not be considered expired")
	})

	t.Run("Token with zero ExpiresAt is never considered expired", func(t *testing.T) {
		token := AccessToken{
			AccessToken: "test-token",
			ExpiresIn:   json.RawMessage(`3600`),
			ExpiresAt:   time.Time{},
		}

		assert.Equal(t, tokensCache.isTokenExpired(&token), false, "Token with zero ExpiresAt should never be considered expired")
	})

	t.Run("Token that is actually expired is considered expired", func(t *testing.T) {
		token := AccessToken{
			AccessToken: "test-token",
			ExpiresIn:   json.RawMessage(`0`),
			ExpiresAt:   time.Now().UTC().Add(-10 * time.Second),
		}

		assert.Equal(t, tokensCache.isTokenExpired(&token), true, "Actually expired token should be considered expired")
	})

	t.Run("Custom buffer value works correctly", func(t *testing.T) {
		customTokensCache := NewTokensCache(60)

		token := AccessToken{
			AccessToken: "test-token",
			ExpiresIn:   json.RawMessage(`45`),
			ExpiresAt:   time.Now().UTC().Add(45 * time.Second),
		}

		assert.Equal(t, customTokensCache.isTokenExpired(&token), true, "Token should be considered expired with custom 60-second buffer")

		// Same token should not be expired with default 30-second buffer
		defaultTokensCache := NewTokensCache(30)
		assert.Equal(t, defaultTokensCache.isTokenExpired(&token), false, "Token should not be considered expired with default 30-second buffer")
	})
}

func TestNewTokensCacheWithBuffer(t *testing.T) {
	t.Run("TokensCache created with custom buffer value", func(t *testing.T) {
		customBuffer := 120
		tokensCache := NewTokensCache(customBuffer)

		token := AccessToken{
			AccessToken: "test-token",
			ExpiresIn:   json.RawMessage(`90`),
			ExpiresAt:   time.Now().UTC().Add(90 * time.Second),
		}

		assert.Equal(t, tokensCache.isTokenExpired(&token), true, "Token should be considered expired with 120-second buffer")
	})

	t.Run("TokensCache created with zero buffer works correctly", func(t *testing.T) {
		tokensCache := NewTokensCache(0) // No buffer

		token := AccessToken{
			AccessToken: "test-token",
			ExpiresIn:   json.RawMessage(`10`),
			ExpiresAt:   time.Now().UTC().Add(10 * time.Second),
		}

		assert.Equal(t, tokensCache.isTokenExpired(&token), false, "Token should not be considered expired with zero buffer")

		expiredToken := AccessToken{
			AccessToken: "test-token",
			ExpiresIn:   json.RawMessage(`0`),
			ExpiresAt:   time.Now().UTC().Add(-1 * time.Second),
		}

		assert.Equal(t, tokensCache.isTokenExpired(&expiredToken), true, "Actually expired token should be considered expired even with zero buffer")
	})
}
