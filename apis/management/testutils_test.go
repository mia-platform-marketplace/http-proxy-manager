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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"proxy-manager/apis/middlewares"
	"proxy-manager/internal/config"
	proxyservice "proxy-manager/services/proxies"

	"github.com/mia-platform/go-crud-service-client"
	"gotest.tools/assert"
)

var (
	testAuthMethod = "oauth2"
	testGrantType  = "password"
	testUsername   = "SomeUsername"
	testPassword   = "ThisShouldNotBeReturned"

	emptyString = ""
)

func GetMockedRequest(
	t *testing.T,
	method string, path string, body io.Reader,
	crudClient crud.CrudClient[proxyservice.CrudProxy],
	env config.EnvironmentVariables,
) *http.Request {
	ctx := getMockedContext()

	newCtx := middlewares.GetContextWithDependencies(
		context.WithValue(
			context.WithValue(
				ctx,
				middlewares.CrudClientKey[proxyservice.CrudProxy]{},
				crudClient,
			),
			middlewares.EnvKey{},
			env,
		),
	)

	t.Helper()
	req := httptest.NewRequest(method, path, body)
	req = req.WithContext(newCtx)

	return req
}

func getMockedContext() context.Context {
	return context.Background()
}

func CreateRequestBody(t *testing.T, body interface{}) io.Reader {
	t.Helper()

	bodyBytes, err := json.Marshal(body)
	assert.NilError(t, err)
	return bytes.NewBuffer(bodyBytes)
}

func AddRequestQueryParams(t *testing.T, req *http.Request, queryParams map[string]string) {
	t.Helper()
	query := req.URL.Query()
	for key, value := range queryParams {
		query.Add(key, value)
	}
	req.URL.RawQuery = query.Encode()
}
