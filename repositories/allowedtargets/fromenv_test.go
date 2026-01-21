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
	"net/url"
	"proxy-manager/internal/config"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFromEnv(t *testing.T) {
	t.Run("returns repository on env not set", func(t *testing.T) {
		repo, err := FromENV(config.EnvironmentVariables{})
		require.Nil(t, err)
		require.NotNil(t, repo)
	})

	t.Run("returns repository on empty env", func(t *testing.T) {
		repo, err := FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{},
		})
		require.Nil(t, err)
		require.NotNil(t, repo)
	})

	t.Run("returns repository on env configured", func(t *testing.T) {
		repo, err := FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				"https://host-1.com",
				"https://host-2.com",
			},
		})
		require.Nil(t, err)
		require.NotNil(t, repo)
	})

	t.Run("returns repository on already defined target", func(t *testing.T) {
		repo, err := FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				"https://same-host.com",
				"https://same-host.com",
			},
		})
		require.Nil(t, err)
		require.NotNil(t, repo)
	})

	t.Run("error on invalid target defined", func(t *testing.T) {
		repo, err := FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				string([]byte{0x7f}),
			},
		})
		require.EqualError(t, err, "parse \"\\x7f\": net/url: invalid control character in URL")
		require.Nil(t, repo)
	})

	t.Run("error on missing scheme", func(t *testing.T) {
		repo, err := FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				"myhost.com",
			},
		})
		require.EqualError(t, err, ErrInvalidAllowedProxyTargetURLMissingScheme.Error())
		require.Nil(t, repo)
	})

	t.Run("error on missing hostname", func(t *testing.T) {
		repo, err := FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				"https:/something",
			},
		})
		require.EqualError(t, err, ErrInvalidAllowedProxyTargetURLMissingHost.Error())
		require.Nil(t, repo)
	})

	t.Run("error on invalid path set", func(t *testing.T) {
		repo, err := FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				"https://myhost.com/something",
			},
		})
		require.EqualError(t, err, ErrInvalidAllowedProxyTargetURLPathNotSupported.Error())
		require.Nil(t, repo)
	})

	t.Run("error on invalid trailing slash configured", func(t *testing.T) {
		repo, err := FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				"https://myhost.com/",
			},
		})
		require.EqualError(t, err, ErrInvalidAllowedProxyTargetURLPathNotSupported.Error())
		require.Nil(t, repo)
	})
}

func TestListAll(t *testing.T) {
	t.Run("env not set", func(t *testing.T) {
		repo, _ := FromENV(config.EnvironmentVariables{})

		allowedList := repo.ListAll()
		require.Equal(t, allowedList, []*url.URL{})
	})

	t.Run("emtpy conf variable", func(t *testing.T) {
		repo, _ := FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{},
		})

		allowedList := repo.ListAll()
		require.Equal(t, allowedList, []*url.URL{})
	})

	t.Run("configured allow list", func(t *testing.T) {
		repo, _ := FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				"https://some-host-1",
				"http://some-host-2",
				"https://api.some-host-3",
			},
		})

		allowedList := repo.ListAll()
		require.ElementsMatch(t, allowedList, []*url.URL{
			{
				Scheme: "https",
				Host:   "some-host-1",
			},
			{
				Scheme: "http",
				Host:   "some-host-2",
			},
			{
				Scheme: "https",
				Host:   "api.some-host-3",
			},
		})
	})
}

func TestCountAll(t *testing.T) {
	t.Run("zero if env not set", func(t *testing.T) {
		repo, _ := FromENV(config.EnvironmentVariables{})
		require.Zero(t, repo.CountAll())
	})

	t.Run("zero if empty env", func(t *testing.T) {
		repo, _ := FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{},
		})
		require.Zero(t, repo.CountAll())
	})

	t.Run("correct count if configured", func(t *testing.T) {
		repo, _ := FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				"https://some-host.com",
				"https://another-host.com",
			},
		})
		require.Equal(t, 2, repo.CountAll())
	})
}

func TestFindOne(t *testing.T) {
	t.Run("nil if env not set", func(t *testing.T) {
		repo, _ := FromENV(config.EnvironmentVariables{})
		require.Nil(t, repo.FindOne("https://myhost.com"))
	})

	t.Run("nil if empty env", func(t *testing.T) {
		repo, _ := FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{},
		})
		require.Nil(t, repo.FindOne("https://myhost.com"))
	})

	t.Run("nil if not existing", func(t *testing.T) {
		repo, _ := FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				"https://some-host.com",
				"https://another-host.com",
			},
		})
		require.Nil(t, repo.FindOne("https://not-existing-host.com"))
	})

	t.Run("target Url if existing", func(t *testing.T) {
		repo, _ := FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{
				"https://some-host.com",
				"https://another-host.com",
			},
		})

		found := repo.FindOne("https://some-host.com")
		require.NotNil(t, found)
	})
}
