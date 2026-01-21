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
	"fmt"
	"net/http"

	"github.com/mia-platform/go-crud-service-client"
)

type CrudClientKey[TResource any] struct{}

func CrudClientRegister[TResource any](crudCollectionUrl string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			crudClient, err := crud.NewClient[TResource](crud.ClientOptions{
				BaseURL: crudCollectionUrl,
			})

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			newCtx := context.WithValue(ctx, CrudClientKey[TResource]{}, crudClient)
			next.ServeHTTP(w, r.WithContext(newCtx))
		})
	}
}

func ResolveCrudClient[TResource any](ctx context.Context) (crud.CrudClient[TResource], error) {
	crudClientFromCtx := ctx.Value(CrudClientKey[TResource]{})

	if crudClientFromCtx == nil {
		return nil, fmt.Errorf("no crud client found in context")
	}

	crudClient, ok := crudClientFromCtx.(crud.CrudClient[TResource])
	if !ok {
		return nil, fmt.Errorf("crud client type is not correct")
	}
	return crudClient, nil
}
