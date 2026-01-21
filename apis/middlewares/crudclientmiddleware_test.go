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

package middlewares

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/mia-platform/go-crud-service-client"
	"github.com/stretchr/testify/assert"
)

func TestCrudClientRegister(t *testing.T) {
	t.Run("returns 500 when crud client creation fails", func(t *testing.T) {
		router := mux.NewRouter()
		router.Use(CrudClientRegister[string]("invalid_url"))

		isCalled := false
		router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			isCalled = true
			t.Error("handler should not be called")
		})

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.False(t, isCalled)
	})

	t.Run("creates new crud client and adds to context", func(t *testing.T) {
		isCalled := false
		handler := CrudClientRegister[string]("http://test-collection")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			client, err := ResolveCrudClient[string](r.Context())
			assert.NoError(t, err)
			assert.NotNil(t, client)
			isCalled = true
		}))

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.True(t, isCalled)
	})
}

func TestResolveCrudClient(t *testing.T) {
	t.Run("returns error if crud client is not found in context", func(t *testing.T) {
		_, err := ResolveCrudClient[string](context.Background())
		assert.NotNil(t, err)
		assert.Equal(t, "no crud client found in context", err.Error())
	})

	t.Run("returns error if crud client type is not correct", func(t *testing.T) {
		invalidTypeCrudClient, _ := crud.NewClient[int](crud.ClientOptions{})
		ctx := context.WithValue(context.Background(), CrudClientKey[string]{}, invalidTypeCrudClient)

		_, err := ResolveCrudClient[string](ctx)
		assert.NotNil(t, err)
		assert.Equal(t, "crud client type is not correct", err.Error())
	})

	t.Run("returns crud client if it is found in context", func(t *testing.T) {
		crudClient, _ := crud.NewClient[string](crud.ClientOptions{})
		ctx := context.WithValue(context.Background(), CrudClientKey[string]{}, crudClient)

		crudClientFromCtx, err := ResolveCrudClient[string](ctx)
		assert.Nil(t, err)
		assert.Equal(t, crudClient, crudClientFromCtx)
	})
}
