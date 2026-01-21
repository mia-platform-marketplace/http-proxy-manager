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
	"fmt"
	"sort"
	"strings"
	"testing"

	"proxy-manager/internal/config"

	"github.com/gorilla/mux"
	"gotest.tools/assert"
)

func TestSetupManagementRoutes(t *testing.T) {
	env := config.EnvironmentVariables{ServiceConfigUrl: "http://example.com/config", ExposeManagementAPIs: true}
	router := mux.NewRouter()

	expectedPaths := []string{
		"POST-/-/proxies",
		"GET-/-/proxies",
		"PATCH-/-/proxies/{id}",
		"PATCH-/-/proxies",
		"DELETE-/-/proxies",
	}
	sort.Strings(expectedPaths)

	SetupManagementRoutes(router, env)

	foundPaths := make([]string, 0)
	router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, err := route.GetPathTemplate()
		assert.NilError(t, err, "Unexpected path error during walk")

		methods, err := route.GetMethods()
		assert.NilError(t, err, "Unexpected method error during walk")

		pathWithMethods := fmt.Sprintf("%s-%s", strings.Join(methods, ","), path)

		foundPaths = append(foundPaths, pathWithMethods)
		return nil
	})
	sort.Strings(foundPaths)

	assert.DeepEqual(t, expectedPaths, foundPaths)
}
