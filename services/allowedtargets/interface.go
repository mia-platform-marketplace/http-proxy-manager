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

package allowedtargets

import (
	"context"
	"fmt"
)

type IService interface {
	AssertTargetAllowed(targetBaseURL string) error
}

type IServiceKey struct{}

func RegisterInstance(ctx context.Context, instance IService) context.Context {
	return context.WithValue(ctx, IServiceKey{}, instance)
}

func Resolve(ctx context.Context) (IService, error) {
	instanceFromContext := ctx.Value(IServiceKey{})

	if instanceFromContext == nil {
		return nil, fmt.Errorf("no instance registered in context")
	}

	instance, ok := instanceFromContext.(IService)
	if !ok {
		return nil, fmt.Errorf("registered instance type mismatching")
	}
	return instance, nil
}
