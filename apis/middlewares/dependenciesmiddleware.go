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

	"proxy-manager/internal/config"
	allowedtargets_repository "proxy-manager/repositories/allowedtargets"
	allowedtargets_service "proxy-manager/services/allowedtargets"
)

func DependenciesMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctxWithDeps := GetContextWithDependencies(r.Context())
			next.ServeHTTP(w, r.WithContext(ctxWithDeps))
		})
	}
}

func GetContextWithDependencies(contextWithEnv context.Context) context.Context {
	env, err := ResolveEnvs(contextWithEnv)
	if err != nil {
		panic(err)
	}

	registerDepFns := []func(context.Context, config.EnvironmentVariables) context.Context{
		registerAllowedTargetsService,
	}

	ctx := contextWithEnv
	for _, registerFn := range registerDepFns {
		ctx = registerFn(ctx, env)
	}

	return ctx
}

func registerAllowedTargetsService(
	ctx context.Context,
	env config.EnvironmentVariables,
) context.Context {
	repository, err := allowedtargets_repository.FromENV(env)
	if err != nil {
		panic(err)
	}

	service := allowedtargets_service.New(repository)

	// FIXME: depencency interface/instance registration should be managed at top level (eg: main.go or similar)
	// This middleware (and others in this package too) should be moved from here to the main package
	return allowedtargets_service.RegisterInstance(ctx, service)
}
