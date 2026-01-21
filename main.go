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
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"proxy-manager/apis"
	"proxy-manager/internal/config"
	"proxy-manager/internal/helpers"
	auth "proxy-manager/services/authentication"
	"proxy-manager/services/proxies"

	glogrus "github.com/mia-platform/glogger/v4/loggers/logrus"
)

func main() {
	entrypoint(make(chan os.Signal, 1))
	os.Exit(0)
}

func createProxyCache(env config.EnvironmentVariables) *proxies.ProxyCache {
	if env.DisableProxyCache {
		return nil
	}
	return &proxies.ProxyCache{}
}

func entrypoint(shutdown chan os.Signal) {
	env, err := config.GetEnvVariables()
	if err != nil {
		panic(err.Error())
	}

	// Init logger instance.
	log, err := glogrus.InitHelper(glogrus.InitOptions{Level: env.LogLevel})
	if err != nil {
		panic(err.Error())
	}

	var serviceConfig *config.ServiceConfig
	if env.IsStaticConfiguration() {
		// Load service configuration
		serviceConfig, err = config.LoadServiceConfiguration(env.ServiceConfigPath, env.ServiceConfigFileName)
		if err != nil {
			log.WithError(err).Fatal("fails to load service configuration")
		}
	}

	proxiesCache := createProxyCache(env)
	tokensCache := auth.NewTokensCache(env.TokenPreemptiveExpirySeconds)

	router := apis.SetupRouter(log, serviceConfig, proxiesCache, env, tokensCache)

	srv := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%s", env.HTTPPort),
		Handler: router,
	}

	go func() {
		log.WithField("port", env.HTTPPort).Info("Starting server")
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	// sigterm signal sent from kubernetes
	signal.Notify(shutdown, syscall.SIGTERM)
	// We'll accept graceful shutdowns when quit via  and SIGTERM (Ctrl+/)
	// SIGINT (Ctrl+C), SIGKILL or SIGQUIT will not be caught.
	helpers.GracefulShutdown(srv, shutdown, log, env.DelayShutdownSeconds)
}
