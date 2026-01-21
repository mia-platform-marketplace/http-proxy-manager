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

package proxies

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"proxy-manager/entities"

	"gotest.tools/assert"
)

func TestFetchAndUpdateProxyCache(t *testing.T) {
	proxiesCache := ProxyCache{
		"/service": ProxyCacheItem{
			Expiration: 0,
			Proxy: entities.Proxy{
				Authentication: "old",
				GrantType:      "old",
				TargetBaseUrl:  "old",
				BasePath:       "/service",
				AuthType:       "old",
			},
		},
	}

	t.Run(`fails because CRUD replies with error status code`, func(t *testing.T) {
		crud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			w.WriteHeader(400)
			_, err := w.Write([]byte(`"Bad Request"`))
			assert.Assert(t, err, nil)
		}))
		defer crud.Close()

		err := FetchAndUpdateProxyCache(crud.URL, "/service", &proxiesCache, 60)
		assert.Error(t, err, "CRUD replied with status code 400", "Unexpected error.")
	})

	t.Run(`fails because grantType doesn't respect json schema`, func(t *testing.T) {
		crud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(`[{"authentication":"none","grantType":"unknown","targetBaseUrl":"http://service.com","basePath":"/service","authType":"client_secret_basic"}]`))
			assert.NilError(t, err)
		}))
		defer crud.Close()

		err := FetchAndUpdateProxyCache(crud.URL, "/service", &proxiesCache, 60)
		assert.ErrorContains(t, err, "grantType")
		t.Logf("Expected error: %s.", err.Error())
	})

	t.Run(`fails because authType doesn't respect json schema`, func(t *testing.T) {
		crud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(`[{"authentication":"none","grantType":"client_credentials","targetBaseUrl":"http://service.com","basePath":"/service","authType":22}]`))
			assert.NilError(t, err)
		}))
		defer crud.Close()

		err := FetchAndUpdateProxyCache(crud.URL, "/service", &proxiesCache, 60)
		assert.ErrorContains(t, err, "authType")
		t.Logf("Expected error: %s.", err.Error())
	})

	t.Run(`fails because proxy is not found in CRUD`, func(t *testing.T) {
		crud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			_, err := w.Write([]byte(`[]`))
			assert.NilError(t, err)
		}))
		defer crud.Close()

		err := FetchAndUpdateProxyCache(crud.URL, "/service", &proxiesCache, 60)
		assert.Error(t, err, "proxy not found", "Unexpected error")
	})

	t.Run(`fetch correctly proxy, validate with json schema and update proxy cache`, func(t *testing.T) {
		crud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			assert.Equal(t, req.URL.Query().Get("basePath"), "/service", "Unexpected query")
			_, err := w.Write([]byte(`[{"creatorId":"public","authentication":"none","grantType":"client_credentials","targetBaseUrl":"http://service.com","basePath":"/service","authType":"client_secret_basic"}]`))
			assert.Assert(t, err, nil)
		}))
		defer crud.Close()

		err := FetchAndUpdateProxyCache(crud.URL, "/service", &proxiesCache, 60)
		assert.NilError(t, err, "Unexpected error %s.", err)

		assert.Assert(t, time.Now().Before(time.Unix(proxiesCache["/service"].Expiration, 0)), "Unexpected expiration")
		assert.Equal(t, proxiesCache["/service"].Proxy.Authentication, "none", "Unexpected authentication type")
		assert.Equal(t, proxiesCache["/service"].Proxy.GrantType, "client_credentials", "Unexpected grantType")
		assert.Equal(t, proxiesCache["/service"].Proxy.TargetBaseUrl, "http://service.com", "Unexpected targetBaseUrl")
		assert.Equal(t, proxiesCache["/service"].Proxy.BasePath, "/service", "Unexpected basePath")
		assert.Equal(t, proxiesCache["/service"].Proxy.AuthType, "client_secret_basic", "Unexpected grantType")
	})
}
