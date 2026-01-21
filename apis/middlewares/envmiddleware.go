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

	"proxy-manager/internal/config"
)

type EnvKey struct{}

func EnvMiddleware(envs config.EnvironmentVariables) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := RegisterEnvs(r.Context(), envs)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RegisterEnvs(ctx context.Context, envs config.EnvironmentVariables) context.Context {
	return context.WithValue(ctx, EnvKey{}, envs)
}

func ResolveEnvs(ctx context.Context) (config.EnvironmentVariables, error) {
	envsFromCtx := ctx.Value(EnvKey{})

	if envsFromCtx == nil {
		return config.EnvironmentVariables{}, fmt.Errorf("no envs registered in context")
	}

	envs, ok := envsFromCtx.(config.EnvironmentVariables)
	if !ok {
		return config.EnvironmentVariables{}, fmt.Errorf("registered envs type mismatching")
	}
	return envs, nil
}
