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
	"net/http"
	"testing"

	"proxy-manager/entities"

	"github.com/stretchr/testify/require"
)

func TestGetHeaders(t *testing.T) {
	t.Run("forwards all proxies without any other configuration specified", func(t *testing.T) {
		initialHeaders := http.Header{}
		initialHeaders.Add("Header-1", "some value")
		initialHeaders.Add("Authorization", "some auth token")
		initialHeaders.Add("Cookie", "cookie to forward")
		initialHeaders.Add("Header-4", "some other value")

		headersToProxy := getHeaders(
			&entities.Proxy{
				BasePath:      "/my-api",
				TargetBaseUrl: "http://some-service-com/my-api",
			},
			"",
			&http.Request{
				Header: initialHeaders,
			},
			getHeadersOptions{},
		)

		require.Equal(t, initialHeaders, headersToProxy)
	})

	t.Run("adds Authorization header if a token is specified", func(t *testing.T) {
		initialHeaders := http.Header{}
		initialHeaders.Add("Header-1", "some value")
		initialHeaders.Add("Cookie", "cookie to forward")
		initialHeaders.Add("Header-4", "some other value")

		expectedHeaders := http.Header{}
		expectedHeaders.Add("Header-1", "some value")
		expectedHeaders.Add("Authorization", "Bearer auth token to set")
		expectedHeaders.Add("Cookie", "cookie to forward")
		expectedHeaders.Add("Header-4", "some other value")

		headersToProxy := getHeaders(
			&entities.Proxy{
				BasePath:      "/my-api",
				TargetBaseUrl: "http://some-service-com/my-api",
			},
			"auth token to set",
			&http.Request{
				Header: initialHeaders,
			},
			getHeadersOptions{},
		)

		require.Equal(t, expectedHeaders, headersToProxy)
	})

	t.Run("overrides Authorization header if a token is specified", func(t *testing.T) {
		initialHeaders := http.Header{}
		initialHeaders.Add("Header-1", "some value")
		initialHeaders.Add("Authorization", "some auth token")
		initialHeaders.Add("Cookie", "cookie to forward")
		initialHeaders.Add("Header-4", "some other value")

		expectedHeaders := http.Header{}
		expectedHeaders.Add("Header-1", "some value")
		expectedHeaders.Add("Authorization", "Bearer auth token to set")
		expectedHeaders.Add("Cookie", "cookie to forward")
		expectedHeaders.Add("Header-4", "some other value")

		headersToProxy := getHeaders(
			&entities.Proxy{
				BasePath:      "/my-api",
				TargetBaseUrl: "http://some-service-com/my-api",
			},
			"auth token to set",
			&http.Request{
				Header: initialHeaders,
			},
			getHeadersOptions{},
		)

		require.Equal(t, expectedHeaders, headersToProxy)
	})

	t.Run("adds only HeadersToProxy from request if specified", func(t *testing.T) {
		initialHeaders := http.Header{}
		initialHeaders.Add("Header-1", "some value")
		initialHeaders.Add("Authorization", "some auth token")
		initialHeaders.Add("Cookie", "cookie to forward")
		initialHeaders.Add("Header-4", "some other value")

		expectedHeaders := http.Header{}
		expectedHeaders.Add("Header-1", "some value")
		expectedHeaders.Add("Header-4", "some other value")

		headersToProxy := getHeaders(
			&entities.Proxy{
				BasePath:      "/my-api",
				TargetBaseUrl: "http://some-service-com/my-api",
				HeadersToProxy: []string{
					"Header-1",
					"Header-4",
				},
			},
			"",
			&http.Request{
				Header: initialHeaders,
			},
			getHeadersOptions{},
		)

		require.Equal(t, expectedHeaders, headersToProxy)
	})

	t.Run("adds AdditionalHeaders if specified", func(t *testing.T) {
		initialHeaders := http.Header{}
		initialHeaders.Add("Header-1", "some value")
		initialHeaders.Add("Authorization", "some auth token")
		initialHeaders.Add("Cookie", "cookie to forward")
		initialHeaders.Add("Header-4", "some other value")

		expectedHeaders := http.Header{}
		expectedHeaders.Add("Header-1", "some value")
		expectedHeaders.Add("Authorization", "some auth token")
		expectedHeaders.Add("Cookie", "cookie to forward")
		expectedHeaders.Add("Header-4", "some other value")
		expectedHeaders.Add("X-Custom-Header-1", "hello world")
		expectedHeaders.Add("X-Other-Header", "1234")

		headersToProxy := getHeaders(
			&entities.Proxy{
				BasePath:      "/my-api",
				TargetBaseUrl: "http://some-service-com/my-api",
				AdditionalHeaders: []entities.AdditionalHeader{
					{
						Name:  "X-Custom-Header-1",
						Value: "hello world",
					},
					{
						Name:  "X-Other-Header",
						Value: "1234",
					},
				},
			},
			"",
			&http.Request{
				Header: initialHeaders,
			},
			getHeadersOptions{},
		)

		require.Equal(t, expectedHeaders, headersToProxy)
	})

	t.Run("adds AdditionalHeaders if specified", func(t *testing.T) {
		initialHeaders := http.Header{}
		initialHeaders.Add("Header-1", "some value")
		initialHeaders.Add("Authorization", "some auth token")
		initialHeaders.Add("Cookie", "cookie to forward")
		initialHeaders.Add("Header-4", "some other value")

		expectedHeaders := http.Header{}
		expectedHeaders.Add("Header-1", "some value")
		expectedHeaders.Add("Authorization", "some auth token")
		expectedHeaders.Add("Cookie", "cookie to forward")
		expectedHeaders.Add("Header-4", "some other value")
		expectedHeaders.Add("X-Custom-Header-1", "hello world")
		expectedHeaders.Add("X-Other-Header", "1234")

		headersToProxy := getHeaders(
			&entities.Proxy{
				BasePath:      "/my-api",
				TargetBaseUrl: "http://some-service-com/my-api",
				AdditionalHeaders: []entities.AdditionalHeader{
					{
						Name:  "X-Custom-Header-1",
						Value: "hello world",
					},
					{
						Name:  "X-Other-Header",
						Value: "1234",
					},
				},
			},
			"",
			&http.Request{
				Header: initialHeaders,
			},
			getHeadersOptions{},
		)

		require.Equal(t, expectedHeaders, headersToProxy)
	})

	t.Run("adds AdditionalHeaders in list if header is already present", func(t *testing.T) {
		initialHeaders := http.Header{}
		initialHeaders.Add("Header-1", "some value")
		initialHeaders.Add("Authorization", "some auth token")
		initialHeaders.Add("Cookie", "cookie to forward")
		initialHeaders.Add("Header-4", "some other value")

		expectedHeaders := http.Header{}
		expectedHeaders.Add("Header-1", "some value")
		expectedHeaders.Add("Authorization", "some auth token")
		expectedHeaders.Add("Authorization", "some other auth token")
		expectedHeaders.Add("Cookie", "cookie to forward")
		expectedHeaders.Add("Cookie", "other cookie to forward")
		expectedHeaders.Add("Header-4", "some other value")

		headersToProxy := getHeaders(
			&entities.Proxy{
				BasePath:      "/my-api",
				TargetBaseUrl: "http://some-service-com/my-api",
				AdditionalHeaders: []entities.AdditionalHeader{
					{
						Name:  "Authorization",
						Value: "some other auth token",
					},
					{
						Name:  "Cookie",
						Value: "other cookie to forward",
					},
				},
			},
			"",
			&http.Request{
				Header: initialHeaders,
			},
			getHeadersOptions{},
		)

		require.Equal(t, expectedHeaders, headersToProxy)
	})

	t.Run("does not forward headers specified in headersBlockList", func(t *testing.T) {
		initialHeaders := http.Header{}
		initialHeaders.Add("Header-1", "some value")
		initialHeaders.Add("Authorization", "some auth token")
		initialHeaders.Add("Cookie", "cookie to forward")
		initialHeaders.Add("Header-4", "some other value")

		expectedHeaders := http.Header{}
		expectedHeaders.Add("Header-1", "some value")
		expectedHeaders.Add("Header-4", "some other value")

		headersToProxy := getHeaders(
			&entities.Proxy{
				BasePath:      "/my-api",
				TargetBaseUrl: "http://some-service-com/my-api",
				AdditionalHeaders: []entities.AdditionalHeader{
					{
						Name:  "Authorization",
						Value: "some other auth token",
					},
					{
						Name:  "Cookie",
						Value: "other cookie to forward",
					},
				},
			},
			"",
			&http.Request{
				Header: initialHeaders,
			},
			getHeadersOptions{
				HeadersToBlock: []string{"Cookie", "Authorization"},
			},
		)

		require.Equal(t, expectedHeaders, headersToProxy)
	})

	t.Run("remaps headers specified in headersToRemap env", func(t *testing.T) {
		initialHeaders := http.Header{}
		initialHeaders.Add("Header-1", "some value")
		initialHeaders.Add("Internal-User-Id", "user-id-to-forward-remapped")
		initialHeaders.Add("Other-Header", "some other value")
		initialHeaders.Add("Internal-Request-Id", "request-id-to-forward-remapped")

		expectedHeaders := http.Header{}
		expectedHeaders.Add("Header-1", "some value")
		expectedHeaders.Add("X-User-Id", "user-id-to-forward-remapped")
		expectedHeaders.Add("Other-Header", "some other value")
		expectedHeaders.Add("X-Req-Id", "request-id-to-forward-remapped")

		headersToProxy := getHeaders(
			&entities.Proxy{
				BasePath:      "/my-api",
				TargetBaseUrl: "http://some-service-com/my-api",
			},
			"",
			&http.Request{
				Header: initialHeaders,
			},
			getHeadersOptions{
				HeadersToRemap: map[string]string{
					"Internal-User-Id":    "X-User-Id",
					"Internal-Request-Id": "X-Req-Id",
				},
			},
		)

		require.Equal(t, expectedHeaders, headersToProxy)
	})

	t.Run("remapping header to itself have no effects", func(t *testing.T) {
		initialHeaders := http.Header{}
		initialHeaders.Add("Header-1", "123")
		initialHeaders.Add("Header-2", "456")

		expectedHeaders := http.Header{}
		expectedHeaders.Add("Header-1", "123")
		expectedHeaders.Add("Header-2", "456")

		headersToProxy := getHeaders(
			&entities.Proxy{
				BasePath:      "/my-api",
				TargetBaseUrl: "http://some-service-com/my-api",
			},
			"",
			&http.Request{
				Header: initialHeaders,
			},
			getHeadersOptions{
				HeadersToRemap: map[string]string{
					"Header-1": "Header-1",
					"Header-2": "Header-2",
				},
			},
		)

		require.Equal(t, expectedHeaders, headersToProxy)
	})

	t.Run("remapping header into a blocked one gets blocked", func(t *testing.T) {
		initialHeaders := http.Header{}
		initialHeaders.Add("Header-1", "123")
		initialHeaders.Add("Header-To-Remap", "remapped")
		initialHeaders.Add("Header-To-Block", "secret")

		expectedHeaders := http.Header{}
		expectedHeaders.Add("Header-1", "123")

		headersToProxy := getHeaders(
			&entities.Proxy{
				BasePath:      "/my-api",
				TargetBaseUrl: "http://some-service-com/my-api",
			},
			"",
			&http.Request{
				Header: initialHeaders,
			},
			getHeadersOptions{
				HeadersToBlock: []string{"Header-To-Block"},
				HeadersToRemap: map[string]string{
					"Header-To-Remap": "Header-To-Block",
				},
			},
		)

		require.Equal(t, expectedHeaders, headersToProxy)
	})

	t.Run("remapping a HeaderToBlock gets the header remapped", func(t *testing.T) {
		initialHeaders := http.Header{}
		initialHeaders.Add("Header-1", "123")
		initialHeaders.Add("Header-To-Block", "secret")

		expectedHeaders := http.Header{}
		expectedHeaders.Add("Header-1", "123")
		expectedHeaders.Add("Remapped-Header-To-Block", "secret")

		headersToProxy := getHeaders(
			&entities.Proxy{
				BasePath:      "/my-api",
				TargetBaseUrl: "http://some-service-com/my-api",
			},
			"",
			&http.Request{
				Header: initialHeaders,
			},
			getHeadersOptions{
				HeadersToBlock: []string{"Header-To-Block"},
				HeadersToRemap: map[string]string{
					"Header-To-Block": "Remapped-Header-To-Block",
				},
			},
		)

		require.Equal(t, expectedHeaders, headersToProxy)
	})

	t.Run("remapping AdditionalHeader has no effects", func(t *testing.T) {
		initialHeaders := http.Header{}
		initialHeaders.Add("Header-1", "123")

		expectedHeaders := http.Header{}
		expectedHeaders.Add("Header-1", "123")
		expectedHeaders.Add("X-Additional-Header", "hello world")

		headersToProxy := getHeaders(
			&entities.Proxy{
				BasePath:      "/my-api",
				TargetBaseUrl: "http://some-service-com/my-api",
				AdditionalHeaders: []entities.AdditionalHeader{
					{
						Name:  "X-Additional-Header",
						Value: "hello world",
					},
				},
			},
			"",
			&http.Request{
				Header: initialHeaders,
			},
			getHeadersOptions{
				HeadersToBlock: []string{"Header-To-Block"},
				HeadersToRemap: map[string]string{
					"X-Additional-Header": "X-Remapped-Additional-Header",
				},
			},
		)

		require.Equal(t, expectedHeaders, headersToProxy)
	})

	t.Run("remapping an HeaderToProxy gets the header to proxy remapped", func(t *testing.T) {
		initialHeaders := http.Header{}
		initialHeaders.Add("Header-1", "123")
		initialHeaders.Add("X-Header-To-Proxy", "hello world")

		expectedHeaders := http.Header{}
		expectedHeaders.Add("Header-1", "123")
		expectedHeaders.Add("X-Remapped-Header-To-Proxy", "hello world")

		headersToProxy := getHeaders(
			&entities.Proxy{
				BasePath:       "/my-api",
				TargetBaseUrl:  "http://some-service-com/my-api",
				HeadersToProxy: []string{"Header-1", "X-Header-To-Proxy"},
			},
			"",
			&http.Request{
				Header: initialHeaders,
			},
			getHeadersOptions{
				HeadersToRemap: map[string]string{
					"X-Header-To-Proxy": "X-Remapped-Header-To-Proxy",
				},
			},
		)

		require.Equal(t, expectedHeaders, headersToProxy)
	})

	t.Run("mixing all the above", func(t *testing.T) {
		initialHeaders := http.Header{}
		initialHeaders.Add("Header-1", "some value")
		initialHeaders.Add("Authorization", "remove me")
		initialHeaders.Add("Cookie", "remove me")
		initialHeaders.Add("Header-4", "some other value")
		initialHeaders.Add("Internal-User-Id", "user-id-to-forward-remapped")
		initialHeaders.Add("lowercase-request-id", "req-id-to-forward-remapped")

		expectedHeaders := http.Header{}
		expectedHeaders.Add("Header-1", "some value")
		expectedHeaders.Add("Header-4", "some other value")
		expectedHeaders.Add("X-Custom-Header-1", "hello world")
		expectedHeaders.Add("X-Other-Header", "1234")
		expectedHeaders.Add("X-User-Id", "user-id-to-forward-remapped")
		expectedHeaders.Add("X-Req-Id", "req-id-to-forward-remapped")
		expectedHeaders.Add("Custom-Cookie", "remove me")

		headersToProxy := getHeaders(
			&entities.Proxy{
				BasePath:      "/my-api",
				TargetBaseUrl: "http://some-service-com/my-api",
				AdditionalHeaders: []entities.AdditionalHeader{
					{
						Name:  "X-Custom-Header-1",
						Value: "hello world",
					},
					{
						Name:  "X-Other-Header",
						Value: "1234",
					},
				},
				HeadersToProxy: []string{
					"Header-1",
					"Header-4",
					"Authorization",
					"Cookie",
				},
			},
			"my token here",
			&http.Request{
				Header: initialHeaders,
			},
			getHeadersOptions{
				HeadersToBlock: []string{"Cookie", "Authorization"},
				HeadersToRemap: map[string]string{
					"Internal-User-Id": "X-User-Id",

					// NOTE: this one is tested with uppercase variant as standard header naming convention
					"lowercase-request-id": "x-req-id",

					// NOTE: ensuring remapping header to itself gets removed
					"Authorization": "Authorization",

					// NOTE: Remapping blocked header to something else is still permitted even tough not encouraged
					"Cookie": "Custom-Cookie",
				},
			},
		)

		require.Equal(t, expectedHeaders, headersToProxy)
	})
}
