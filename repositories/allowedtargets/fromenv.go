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
	"fmt"
	"net/url"

	"proxy-manager/internal/config"
)

type repositoryFromENV struct {
	allowedURLMap map[string]*url.URL
}

var (
	ErrInvalidAllowedProxyTargetURLMissingScheme    = fmt.Errorf("invalid allowed target url: missing required schema")
	ErrInvalidAllowedProxyTargetURLMissingHost      = fmt.Errorf("invalid allowed target url: missing required hostname")
	ErrInvalidAllowedProxyTargetURLPathNotSupported = fmt.Errorf("invalid allowed target url: path should not be defined in target url")
)

func FromENV(env config.EnvironmentVariables) (IAllowedTargetsRepository, error) {
	allowedMap := map[string]*url.URL{}

	for _, allowedTarget := range env.AllowedProxyTargetURLs {
		allowedURL, err := url.Parse(allowedTarget)
		if err != nil {
			return nil, err
		}

		if allowedURL.Scheme == "" {
			return nil, ErrInvalidAllowedProxyTargetURLMissingScheme
		}
		if allowedURL.Host == "" {
			return nil, ErrInvalidAllowedProxyTargetURLMissingHost
		}
		if allowedURL.Path != "" {
			return nil, ErrInvalidAllowedProxyTargetURLPathNotSupported
		}

		if allowedMap[allowedTarget] != nil {
			// already defined, skip
			continue
		}

		allowedMap[allowedTarget] = allowedURL
	}

	repo := repositoryFromENV{
		allowedURLMap: allowedMap,
	}

	return repo, nil
}

func (r repositoryFromENV) ListAll() []*url.URL {
	v := make([]*url.URL, 0, len(r.allowedURLMap))

	for _, value := range r.allowedURLMap {
		v = append(v, value)
	}

	return v
}

func (r repositoryFromENV) FindOne(baseURL string) *url.URL {
	return r.allowedURLMap[baseURL]
}

func (r repositoryFromENV) CountAll() int {
	return len(r.allowedURLMap)
}
