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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"proxy-manager/entities"
	"proxy-manager/internal/config"

	"gotest.tools/assert"
)

func TestFinalizeTargetBaseURL(t *testing.T) {
	testCases := []struct {
		baseURL  string
		path     string
		expected string
	}{
		{
			baseURL:  "https://some-url",
			path:     "a/b",
			expected: "https://some-url/a/b",
		},
		{
			baseURL:  "https://some-url/",
			path:     "a/b",
			expected: "https://some-url/a/b",
		},
		{
			baseURL:  "https://some-url",
			path:     "/a/b",
			expected: "https://some-url/a/b",
		},
		{
			baseURL:  "https://some-url/",
			path:     "/a/b",
			expected: "https://some-url/a/b",
		},
	}
	for i, test := range testCases {
		t.Run(fmt.Sprintf("test case #%d %s + %s -> %s", i+1, test.baseURL, test.path, test.expected), func(t *testing.T) {
			assert.Equal(t, finalizeTargetBaseURL(test.baseURL, test.path), test.expected)
		})
	}
}

func TestRetrieveURL(t *testing.T) {
	req := func(url string) *http.Request { return httptest.NewRequest(http.MethodGet, url, nil) }
	proxy := func(targetBaseURL, basePath string) *entities.Proxy {
		return &entities.Proxy{TargetBaseUrl: targetBaseURL, BasePath: basePath}
	}

	testCases := []struct {
		name     string
		dynProxy bool
		proxy    *entities.Proxy
		req      *http.Request
		matchers []string
		expected string
	}{
		{
			name:     "sanitize target base url with trailing slash",
			req:      req("https://some-host/some-original-path/path1/path2"),
			proxy:    proxy("https://another-host/", "/path1/path2"),
			expected: "https://another-host/some-original-path/path1/path2",
		},
		{
			name:     "sanitize target base url with trailing slash with dynamic proxy",
			req:      req("https://some-host/some-original-path/path1/path2"),
			proxy:    proxy("https://another-host/", "/path1/path2"),
			expected: "https://another-host/path1/path2",
			dynProxy: true,
		},
		{
			name:     "extract basepath with dynamic proxy configuration",
			req:      req("https://some-host/some-original-path/path1/path2"),
			proxy:    proxy("https://another-host", "/path1/path2"),
			expected: "https://another-host/path1/path2",
			dynProxy: true,
		},
		{
			name:     "extract basepath with dynamic proxy configuration and base path with matcher",
			req:      req("https://some-host/extensions/1234567/path1/path2"),
			proxy:    proxy("https://another-host", "/extensions/1234567"),
			expected: "https://another-host/path1/path2",
			matchers: []string{"/extensions/:id"},
			dynProxy: true,
		},
	}

	for i, test := range testCases {
		t.Run(fmt.Sprintf("test case #%d %s", i+1, test.name), func(t *testing.T) {
			env := config.EnvironmentVariables{}
			if test.dynProxy {
				env.ServiceConfigUrl = "the service config url"
			}
			if len(test.matchers) > 0 {
				env.BasePathExtractorPrefixes = test.matchers
			}

			result := retrieveUrl(nil, env, test.proxy, test.req)
			assert.Equal(t, result, test.expected, "Wrong destination url.")
		})
	}
}
