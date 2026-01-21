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

package main

import (
	"io"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"
)

func TestEntryPoint(t *testing.T) {
	os.Setenv("DELAY_SHUTDOWN_SECONDS", "0")

	t.Run("missing required environment variables", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

		defer func() {
			r := recover()
			require.Equal(t, "required env variables not set", r)
		}()

		entrypoint(shutdown)
	})

	t.Run("opens server on port 3000", func(t *testing.T) {
		t.Run("static configuration", func(t *testing.T) {
			shutdown := make(chan os.Signal, 1)

			os.Setenv("HTTP_PORT", "3000")
			os.Setenv("CONFIGURATION_PATH", "./test-data/")
			os.Setenv("CONFIGURATION_FILE_NAME", "test-config")

			go func() {
				entrypoint(shutdown)
			}()
			defer func() {
				os.Unsetenv("HTTP_PORT")
				os.Unsetenv("CONFIGURATION_PATH")
				os.Unsetenv("CONFIGURATION_FILE_NAME")
				shutdown <- syscall.SIGTERM
			}()

			time.Sleep(1 * time.Second)

			resp, err := http.DefaultClient.Get("http://localhost:3000/-/healthz")
			require.Equal(t, nil, err)
			require.Equal(t, 200, resp.StatusCode)
		})

		t.Run("dynamic configuration", func(t *testing.T) {
			shutdown := make(chan os.Signal, 1)

			os.Setenv("HTTP_PORT", "3000")
			os.Setenv("CONFIGURATION_URL", "http://crud-service/proxies")
			os.Setenv("EXPOSE_MANAGEMENT_APIS", "false")

			go func() {
				entrypoint(shutdown)
			}()
			defer func() {
				os.Unsetenv("HTTP_PORT")
				os.Unsetenv("CONFIGURATION_URL")
				os.Unsetenv("EXPOSE_MANAGEMENT_APIS")
				shutdown <- syscall.SIGTERM
			}()

			time.Sleep(1 * time.Second)

			resp, err := http.DefaultClient.Get("http://localhost:3000/-/healthz")

			require.Equal(t, nil, err)
			require.Equal(t, 200, resp.StatusCode)
		})

		t.Run("dynamic configuration with management APIs", func(t *testing.T) {
			shutdown := make(chan os.Signal, 1)

			os.Setenv("HTTP_PORT", "3000")
			os.Setenv("CONFIGURATION_URL", "http://crud-service/proxies")
			os.Setenv("EXPOSE_MANAGEMENT_APIS", "true")

			go func() {
				entrypoint(shutdown)
			}()
			defer func() {
				os.Unsetenv("HTTP_PORT")
				os.Unsetenv("CONFIGURATION_URL")
				os.Unsetenv("EXPOSE_MANAGEMENT_APIS")
				shutdown <- syscall.SIGTERM
			}()

			time.Sleep(1 * time.Second)

			resp, err := http.DefaultClient.Get("http://localhost:3000/-/healthz")

			require.Equal(t, nil, err)
			require.Equal(t, 200, resp.StatusCode)
		})
	})

	t.Run("sets correct path prefix", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworking()

		gock.New("http://other-service.com").
			Get("/").
			Reply(200).
			JSON(map[string]string{"status": "ok"})

		gock.New("http://localhost:8080").
			EnableNetworking()

		shutdown := make(chan os.Signal, 1)

		os.Setenv("CONFIGURATION_PATH", "./test-data/")
		os.Setenv("CONFIGURATION_FILE_NAME", "test-config")
		os.Setenv("SERVICE_PREFIX", "/prefix")

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			os.Unsetenv("CONFIGURATION_PATH")
			os.Unsetenv("CONFIGURATION_FILE_NAME")
			os.Unsetenv("SERVICE_PREFIX")
			shutdown <- syscall.SIGTERM
		}()

		time.Sleep(1 * time.Second)

		resp, err := http.DefaultClient.Get("http://localhost:8080/prefix/other-service/")
		require.Equal(t, nil, err)
		require.Equal(t, 200, resp.StatusCode)
	})

	t.Run("GracefulShutdown works properly", func(t *testing.T) {
		os.Setenv("CONFIGURATION_PATH", "./test-data/")
		os.Setenv("CONFIGURATION_FILE_NAME", "test-config")
		os.Setenv("DELAY_SHUTDOWN_SECONDS", "3")

		shutdown := make(chan os.Signal, 1)
		done := make(chan bool, 1)

		go func() {
			time.Sleep(5 * time.Second)
			done <- false
			os.Unsetenv("CONFIGURATION_PATH")
			os.Unsetenv("CONFIGURATION_FILE_NAME")
			os.Unsetenv("DELAY_SHUTDOWN_SECONDS")
		}()

		go func() {
			entrypoint(shutdown)
			done <- true
		}()
		shutdown <- syscall.SIGTERM

		flag := <-done
		require.Equal(t, true, flag)
	})

	t.Run("handles path parameters", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworking()

		gock.New("https://docs.mia-platform.eu").
			Get("/docs/release-notes/v11.0.0").
			Reply(200).
			JSON(map[string]string{"version": "11"})

		gock.New("http://localhost:3000").
			EnableNetworking()

		shutdown := make(chan os.Signal, 1)

		os.Setenv("HTTP_PORT", "3000")
		os.Setenv("CONFIGURATION_PATH", "./test-data/")
		os.Setenv("CONFIGURATION_FILE_NAME", "test-config")

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			os.Unsetenv("HTTP_PORT")
			os.Unsetenv("CONFIGURATION_PATH")
			os.Unsetenv("CONFIGURATION_FILE_NAME")
			shutdown <- syscall.SIGTERM
		}()

		time.Sleep(1 * time.Second)

		resp, err := http.DefaultClient.Get("http://localhost:3000/mia/v11.0.0")
		require.Equal(t, nil, err)
		require.Equal(t, 200, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		require.Equal(t, string(body)[:16], `{"version":"11"}`)
	})
}
