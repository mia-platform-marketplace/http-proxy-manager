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

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"proxy-manager/entities"

	"gotest.tools/assert"
)

func TestLoadServiceConfiguration(t *testing.T) {
	createFile := func(filename string, config ServiceConfig) (*os.File, string, string) {
		t.Helper()
		file, err := os.CreateTemp("", fmt.Sprintf("%s*.json", filename))
		if err != nil {
			t.Fatal(err)
		}

		content, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(file.Name(), content, os.ModePerm); err != nil {
			t.Fatal(err)
		}

		t.Logf("Created file: %s", file.Name())
		tmpDir := strings.Split(file.Name(), filename)[0]

		randomPart := strings.Split(file.Name(), filename)[1]
		return file, strings.TrimSuffix(fmt.Sprintf("./%s%s", filename, randomPart), ".json"), tmpDir
	}

	t.Run(`fails because it does not find config file`, func(t *testing.T) {
		_, err := LoadServiceConfiguration("someInvalid", "filename")
		assert.Assert(t, err != nil, "Unxpected nil error.")
		t.Logf("Expected error: %s.", err.Error())
	})

	t.Run(`fails because config has no required properties`, func(t *testing.T) {
		file, filename, tmpDir := createFile("testfile", ServiceConfig{})
		defer os.Remove(file.Name())

		_, err := LoadServiceConfiguration(tmpDir, filename)
		assert.Assert(t, err != nil, "An error was expected.")
		t.Logf("Expected error: %s.", err.Error())
	})

	t.Run(`read correctly configuration, validate with json schema and set to config structure`, func(t *testing.T) {
		config, err := LoadServiceConfiguration("../../test-data/", "test-config")
		assert.Equal(t, err, nil, "Unexpected error %s.", err)
		assert.Equal(t, len(config.Proxies), 5, "Unexpected config Clients length.")

		assert.Equal(t, config.Proxies[0].Authentication, "oauth2", "Unexpected authentication type")
		assert.Equal(t, config.Proxies[0].ClientId, "6779ef20e75817b79602", "Unexpected clientId")
		assert.Equal(t, config.Proxies[0].ClientSecret, "GBAyfVL7YWtP6gudLIjbRZV_N0dW", "Unexpected clientSecret")
		assert.Equal(t, config.Proxies[0].TokenIssuerUrl, "http://external-service.com/auth/oauth/token", "Unexpected tokenIssuerUrl")
		assert.Equal(t, config.Proxies[0].TargetBaseUrl, "http://external-service.com", "Unexpected targetBaseUrl")
		assert.Equal(t, config.Proxies[0].BasePath, "/external-service", "Unexpected basePath")
		assert.Equal(t, config.Proxies[0].GrantType, "client_credentials", "Unexpected grantType")
		assert.Equal(t, config.Proxies[0].AuthType, "client_secret_basic", "Unexpected grantType")
		assert.Equal(t, config.Proxies[0].AdditionalHeaders[0].Name, "x-api-key", "Unexpected additionalHeaders")
		assert.Equal(t, config.Proxies[0].AdditionalHeaders[0].Value, "custom-api-key", "Unexpected additionalHeaders")

		assert.Equal(t, config.Proxies[1].Authentication, "oauth2", "Unexpected authentication type")
		assert.Equal(t, config.Proxies[1].ClientId, "6739ef20e75817a79c02", "Unexpected clientId")
		assert.Equal(t, config.Proxies[1].ClientSecret, "GBAfweVL7YWtP6gudLIjbRZV_NdW", "Unexpected clientSecret")
		assert.Equal(t, config.Proxies[1].TokenIssuerUrl, "http://mia-client-credentials.com/auth/oauth/token", "Unexpected tokenIssuerUrl")
		assert.Equal(t, config.Proxies[1].TargetBaseUrl, "https://mia-service.com", "Unexpected targetBaseUrl")
		assert.Equal(t, config.Proxies[1].BasePath, "/mia-service", "Unexpected basePath")
		assert.Equal(t, config.Proxies[1].GrantType, "client_credentials", "Unexpected grantType")
		assert.Equal(t, config.Proxies[1].AuthType, "client_secret_basic", "Unexpected grantType")
		assert.Equal(t, config.Proxies[1].AdditionalAuthFields["audience"], "mia-audience", "Unexpected grantType")

		assert.Equal(t, config.Proxies[2].Authentication, "oauth2", "Unexpected authentication type")
		assert.Equal(t, config.Proxies[2].Username, "username", "Unexpected username value")
		assert.Equal(t, config.Proxies[2].Password, "pwd", "Unexpected password value")
		assert.Equal(t, config.Proxies[2].ClientId, "0fbd65b60ca0388f2069", "Unexpected clientId")
		assert.Equal(t, config.Proxies[2].ClientSecret, "ZUotgSDuyesC6VpZM9P2_mDJPTX4", "Unexpected clientSecret")
		assert.Equal(t, config.Proxies[2].TokenIssuerUrl, "http://external-service.com/auth/oauth/token", "Unexpected tokenIssuerUrl")
		assert.Equal(t, config.Proxies[2].TargetBaseUrl, "http://external-service.com", "Unexpected targetBaseUrl")
		assert.Equal(t, config.Proxies[2].BasePath, "/external-service", "Unexpected basePath")
		assert.Equal(t, config.Proxies[2].GrantType, "password", "Unexpected grantType")
		assert.Equal(t, config.Proxies[2].AuthType, "", "Unexpected grantType")

		assert.Equal(t, config.Proxies[3].TargetBaseUrl, "http://other-service.com", "Unexpected targetBaseUrl")
		assert.Equal(t, config.Proxies[3].BasePath, "/other-service", "Unexpected basePath")

		assert.Equal(t, config.Proxies[4].TargetBaseUrl, "https://docs.mia-platform.eu/docs/release-notes/{version}", "Unexpected targetBaseUrl")
		assert.Equal(t, config.Proxies[4].BasePath, "/mia/{version}", "Unexpected basePath")
	})

	t.Run(`fails because targetBaseUrl doesn't respect json schema - missing http/https`, func(t *testing.T) {
		file, filename, tmpDir := createFile("testfile", ServiceConfig{
			Proxies: []*entities.Proxy{
				{
					Authentication: "none",
					GrantType:      "client_credentials",
					TargetBaseUrl:  "service.com",
					BasePath:       "/service",
					AuthType:       "client_secret_basic",
					HeadersToProxy: []string{"Accept", "Content-Type"},
					AdditionalAuthFields: map[string]string{
						"audience":        "dih",
						"otherCustomProp": "randomValue",
					},
					AdditionalHeaders: []entities.AdditionalHeader{
						{Name: "x-api-key", Value: "custom-api-key"},
					},
				},
			},
		})
		defer os.Remove(file.Name())

		_, err := LoadServiceConfiguration(tmpDir, filename)
		assert.Assert(t, err != nil, "An error was expected.")
	})

	t.Run(`fails because basePath doesn't respect json schema - missing /`, func(t *testing.T) {
		file, filename, tmpDir := createFile("testfile", ServiceConfig{
			Proxies: []*entities.Proxy{
				{
					Authentication: "none",
					GrantType:      "client_credentials",
					TargetBaseUrl:  "http://service.com",
					BasePath:       "service",
					AuthType:       "client_secret_basic",
					HeadersToProxy: []string{"Accept", "Content-Type"},
					AdditionalAuthFields: map[string]string{
						"audience":        "dih",
						"otherCustomProp": "randomValue",
					},
					AdditionalHeaders: []entities.AdditionalHeader{
						{Name: "x-api-key", Value: "custom-api-key"},
					},
				},
			},
		})
		defer os.Remove(file.Name())

		_, err := LoadServiceConfiguration(tmpDir, filename)
		assert.Assert(t, err != nil, "An error was expected.")
	})

	t.Run(`fails because basePath does not contain the same path parameters of targetBaseUrl`, func(t *testing.T) {
		file, filename, tmpDir := createFile("testfile", ServiceConfig{
			Proxies: []*entities.Proxy{
				{
					Authentication: "none",
					GrantType:      "client_credentials",
					TargetBaseUrl:  "http://service.com/{id}",
					BasePath:       "/service",
					AuthType:       "client_secret_basic",
					HeadersToProxy: []string{"Accept", "Content-Type"},
					AdditionalAuthFields: map[string]string{
						"audience":        "dih",
						"otherCustomProp": "randomValue",
					},
					AdditionalHeaders: []entities.AdditionalHeader{
						{Name: "x-api-key", Value: "custom-api-key"},
					},
				},
			},
		})
		defer os.Remove(file.Name())

		_, err := LoadServiceConfiguration(tmpDir, filename)
		assert.Assert(t, err != nil, "An error was expected.")
	})

	t.Run(`fails because wrong path parameter inside targetBaseUrl`, func(t *testing.T) {
		file, filename, tmpDir := createFile("testfile", ServiceConfig{
			Proxies: []*entities.Proxy{
				{
					Authentication: "none",
					GrantType:      "client_credentials",
					TargetBaseUrl:  "http://service.com/{id",
					BasePath:       "/service/{id}",
					AuthType:       "client_secret_basic",
					HeadersToProxy: []string{"Accept", "Content-Type"},
					AdditionalAuthFields: map[string]string{
						"audience":        "dih",
						"otherCustomProp": "randomValue",
					},
					AdditionalHeaders: []entities.AdditionalHeader{
						{Name: "x-api-key", Value: "custom-api-key"},
					},
				},
			},
		})
		defer os.Remove(file.Name())

		_, err := LoadServiceConfiguration(tmpDir, filename)
		assert.Assert(t, err != nil, "An error was expected.")
	})
}

func TestGetEnvVariables(t *testing.T) {
	t.Run(`fails because wrong env type`, func(t *testing.T) {
		t.Setenv("PROXY_CACHE_TTL", "aaaa")

		_, err := GetEnvVariables()
		assert.ErrorContains(t, err, "ProxyCacheTTL")
		t.Logf("Expected error: %s.", err.Error())
	})

	t.Run(`fails because missing required variables`, func(t *testing.T) {
		_, err := GetEnvVariables()
		assert.Error(t, err, "required env variables not set")
	})

	t.Run(`fails because are set too many envs`, func(t *testing.T) {
		t.Setenv("CONFIGURATION_PATH", "something1")
		t.Setenv("CONFIGURATION_FILE_NAME", "something2")
		t.Setenv("CONFIGURATION_URL", "something3")

		_, err := GetEnvVariables()
		assert.Error(t, err, "cannot enable both dynamic and static configuration")
	})

	t.Run(`fails because missing slash before SERVICE_PREFIX`, func(t *testing.T) {
		t.Setenv("CONFIGURATION_URL", "something")
		t.Setenv("SERVICE_PREFIX", "service-prefix")

		_, err := GetEnvVariables()
		assert.Error(t, err, "service prefix does not match the following regex: ^/[a-zA-Z0-9_-]+$")
	})

	t.Run(`fails because wrong character inside SERVICE_PREFIX`, func(t *testing.T) {
		t.Setenv("CONFIGURATION_URL", "something")
		t.Setenv("SERVICE_PREFIX", "/service-p?refix")

		_, err := GetEnvVariables()
		assert.Error(t, err, "service prefix does not match the following regex: ^/[a-zA-Z0-9_-]+$")
	})

	t.Run(`fails because wrong character at the end of SERVICE_PREFIX`, func(t *testing.T) {
		t.Setenv("CONFIGURATION_URL", "something")
		t.Setenv("SERVICE_PREFIX", "/service-prefix?")

		_, err := GetEnvVariables()
		assert.Error(t, err, "service prefix does not match the following regex: ^/[a-zA-Z0-9_-]+$")
	})

	t.Run(`fails because wrong character at the beginning of SERVICE_PREFIX`, func(t *testing.T) {
		t.Setenv("CONFIGURATION_URL", "something")
		t.Setenv("SERVICE_PREFIX", "?/service-prefix")

		_, err := GetEnvVariables()
		assert.Error(t, err, "service prefix does not match the following regex: ^/[a-zA-Z0-9_-]+$")
	})

	t.Run(`fails because SERVICE_PREFIX has no characters after /`, func(t *testing.T) {
		t.Setenv("CONFIGURATION_URL", "something")
		t.Setenv("SERVICE_PREFIX", "/")

		_, err := GetEnvVariables()
		assert.Error(t, err, "service prefix does not match the following regex: ^/[a-zA-Z0-9_-]+$")

	})

	t.Run(`Environment variables retrieved successfully`, func(t *testing.T) {
		t.Setenv("LOG_LEVEL", "info")
		t.Setenv("HTTP_PORT", "8080")
		t.Setenv("ALLOW_PROXY_OPTIMIZER", "true")
		t.Setenv("DELAY_SHUTDOWN_SECONDS", "10")
		t.Setenv("CONFIGURATION_URL", "something")
		t.Setenv("SERVICE_PREFIX", "/service-prefix")
		t.Setenv("EXPOSE_MANAGEMENT_APIS", "true")

		env, err := GetEnvVariables()
		assert.NilError(t, err, "Unexpected error")
		assert.DeepEqual(t, env, EnvironmentVariables{
			LogLevel:                     "info",
			HTTPPort:                     "8080",
			AllowProxyOptimizer:          true,
			DelayShutdownSeconds:         10,
			ServiceConfigUrl:             "something",
			ServicePrefix:                "/service-prefix",
			ExposeManagementAPIs:         true,
			TokenPreemptiveExpirySeconds: 30,
		})
	})

	t.Run("AdditionalHeadersToRedact", func(t *testing.T) {
		t.Setenv("LOG_LEVEL", "info")
		t.Setenv("HTTP_PORT", "8080")
		t.Setenv("ALLOW_PROXY_OPTIMIZER", "true")
		t.Setenv("DELAY_SHUTDOWN_SECONDS", "10")
		t.Setenv("CONFIGURATION_URL", "something")

		t.Setenv("ADDITIONAL_HEADERS_TO_REDACT", "h1,h2")

		env, err := GetEnvVariables()
		assert.NilError(t, err, "Unexpected error")
		assert.DeepEqual(t, []string{"h1", "h2"}, env.AdditionalHeadersToRedact)
	})

	t.Run("BasePathExtractorPrefixes", func(t *testing.T) {
		t.Setenv("LOG_LEVEL", "info")
		t.Setenv("HTTP_PORT", "8080")
		t.Setenv("ALLOW_PROXY_OPTIMIZER", "true")
		t.Setenv("DELAY_SHUTDOWN_SECONDS", "10")
		t.Setenv("CONFIGURATION_URL", "something")

		t.Run("var not set", func(t *testing.T) {
			env, err := GetEnvVariables()
			assert.NilError(t, err, "Unexpected error")
			assert.Assert(t, env.BasePathExtractorPrefixes == nil)
		})

		t.Run("var properly set", func(t *testing.T) {
			t.Setenv("BASE_PATH_MATCHERS", "/a,/b")

			env, err := GetEnvVariables()
			assert.NilError(t, err, "Unexpected error")
			assert.DeepEqual(t, []string{"/a", "/b"}, env.BasePathExtractorPrefixes)
		})
	})

	t.Run("HeadersToRemap", func(t *testing.T) {
		t.Setenv("LOG_LEVEL", "info")
		t.Setenv("HTTP_PORT", "8080")
		t.Setenv("ALLOW_PROXY_OPTIMIZER", "true")
		t.Setenv("DELAY_SHUTDOWN_SECONDS", "10")
		t.Setenv("CONFIGURATION_URL", "something")

		t.Run("var not set", func(t *testing.T) {
			env, err := GetEnvVariables()
			assert.NilError(t, err, "Unexpected error")
			assert.Assert(t, env.HeaderBlockList == nil)
		})

		t.Run("var properly set", func(t *testing.T) {
			t.Setenv("HEADER_BLOCK_LIST", "User-Id,Cookie,Api-Key")

			env, err := GetEnvVariables()
			assert.NilError(t, err, "Unexpected error")
			assert.DeepEqual(t, []string{"User-Id", "Cookie", "Api-Key"}, env.HeaderBlockList)
		})
	})

	t.Run("HeaderRemapList", func(t *testing.T) {
		t.Setenv("LOG_LEVEL", "info")
		t.Setenv("HTTP_PORT", "8080")
		t.Setenv("ALLOW_PROXY_OPTIMIZER", "true")
		t.Setenv("DELAY_SHUTDOWN_SECONDS", "10")
		t.Setenv("CONFIGURATION_URL", "something")

		t.Run("var not set", func(t *testing.T) {
			env, err := GetEnvVariables()
			assert.NilError(t, err, "Unexpected error")
			assert.Assert(t, env.HeadersToRemap == nil)
		})

		t.Run("var properly set", func(t *testing.T) {
			t.Setenv("HEADERS_TO_REMAP", "X-Secret-Header:X-Custom-Header,x-only-internal-header:x-header-to-expose")

			env, err := GetEnvVariables()
			assert.NilError(t, err, "Unexpected error")
			assert.DeepEqual(t, map[string]string{
				"X-Secret-Header":        "X-Custom-Header",
				"x-only-internal-header": "x-header-to-expose",
			}, env.HeadersToRemap)
		})
	})

	t.Run("DisallowedResponseContentTypes", func(t *testing.T) {
		t.Setenv("CONFIGURATION_URL", "something")

		t.Run("var not set", func(t *testing.T) {
			env, err := GetEnvVariables()
			assert.NilError(t, err, "Unexpected error")
			assert.Assert(t, env.DisallowedResponseContentTypes == nil)
		})

		t.Run("var properly set with 1 value", func(t *testing.T) {
			t.Setenv("DISALLOWED_RESPONSE_CONTENT_TYPE_LIST", "test1")
			env, err := GetEnvVariables()
			assert.NilError(t, err, "Unexpected error")
			assert.DeepEqual(t, []string{"test1"}, env.DisallowedResponseContentTypes)
		})

		t.Run("var properly set with multiple values", func(t *testing.T) {
			t.Setenv("DISALLOWED_RESPONSE_CONTENT_TYPE_LIST", "test1,test2")
			env, err := GetEnvVariables()
			assert.NilError(t, err, "Unexpected error")
			assert.DeepEqual(t, []string{"test1", "test2"}, env.DisallowedResponseContentTypes)
		})
	})

	t.Run("AllowedProxyTargetList", func(t *testing.T) {
		t.Setenv("LOG_LEVEL", "info")
		t.Setenv("HTTP_PORT", "8080")
		t.Setenv("ALLOW_PROXY_OPTIMIZER", "true")
		t.Setenv("DELAY_SHUTDOWN_SECONDS", "10")
		t.Setenv("CONFIGURATION_URL", "something")

		t.Run("var not set", func(t *testing.T) {
			env, err := GetEnvVariables()
			assert.NilError(t, err, "Unexpected error")
			assert.Assert(t, env.AllowedProxyTargetURLs == nil)
		})

		t.Run("var properly set", func(t *testing.T) {
			t.Setenv("ALLOWED_PROXY_TARGET_URLS", "https://apis.google.com,http://allowed-target")

			env, err := GetEnvVariables()
			assert.NilError(t, err, "Unexpected error")
			assert.DeepEqual(t, []string{
				"https://apis.google.com",
				"http://allowed-target",
			}, env.AllowedProxyTargetURLs)
		})
	})
}
