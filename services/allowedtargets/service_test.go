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
	"testing"

	"proxy-manager/internal/config"
	repository "proxy-manager/repositories/allowedtargets"

	"github.com/stretchr/testify/require"
)

func TestAssertTargetAllowed(t *testing.T) {
	type testCase struct {
		name                   string
		allowedProxyTargetList []string
		targetBaseURL          string
		allowed                bool
	}

	testCases := []testCase{
		{
			name:          "env not set",
			targetBaseURL: "whatever",
			allowed:       true,
		},
		{
			name:                   "env empty",
			allowedProxyTargetList: []string{},
			targetBaseURL:          "whatever",
			allowed:                true,
		},

		{
			name:                   "allowed - only one defined",
			allowedProxyTargetList: []string{"https://api.allowed.com"},
			targetBaseURL:          "https://api.allowed.com/",
			allowed:                true,
		},
		{
			name:                   "not allowed - only one defined",
			allowedProxyTargetList: []string{"https://api.allowed.com"},
			targetBaseURL:          "https://api.not-allowed.com/",
			allowed:                false,
		},
		{
			name:                   "allowed - multiple defined",
			allowedProxyTargetList: []string{"https://api.allowed-1.com", "https://api.allowed-2.com"},
			targetBaseURL:          "https://api.allowed-2.com/",
			allowed:                true,
		},
		{
			name:                   "not allowed - multiple defined",
			allowedProxyTargetList: []string{"https://api.allowed-1.com", "https://api.allowed-2.com"},
			targetBaseURL:          "https://api.allowed-3.com/",
			allowed:                false,
		},

		{
			name:                   "allowed - with subpath",
			allowedProxyTargetList: []string{"https://api.allowed-1.com", "https://api.allowed-2.com"},
			targetBaseURL:          "https://api.allowed-2.com/some/path",
			allowed:                true,
		},
		{
			name:                   "not allowed - with subpath",
			allowedProxyTargetList: []string{"https://api.allowed-1.com", "https://api.allowed-2.com"},
			targetBaseURL:          "https://api.allowed-3.com/some/path",
			allowed:                false,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			repo, err := repository.FromENV(config.EnvironmentVariables{
				AllowedProxyTargetURLs: test.allowedProxyTargetList,
			})
			require.Nil(t, err)

			svc := New(repo)

			err = svc.AssertTargetAllowed(test.targetBaseURL)
			if !test.allowed {
				require.Error(t, err)
				require.Equal(t, ErrNotAllowedTargetURL, err)
			} else {
				require.Nil(t, err)
			}
		})
	}
}
