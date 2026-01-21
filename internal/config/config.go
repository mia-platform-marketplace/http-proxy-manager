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

package config

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"proxy-manager/entities"

	envlib "github.com/caarlos0/env/v11"
	"github.com/mia-platform/configlib"
)

//go:embed config.schema.json
var configSchema string

// EnvironmentVariables struct with the mapping of desired environment variables.
type EnvironmentVariables struct {
	LogLevel                       string            `env:"LOG_LEVEL" envDefault:"info"`
	HTTPPort                       string            `env:"HTTP_PORT" envDefault:"8080"`
	ServicePrefix                  string            `env:"SERVICE_PREFIX"`
	ServiceVersion                 string            `env:"SERVICE_VERSION"`
	ServiceConfigPath              string            `env:"CONFIGURATION_PATH"`
	ServiceConfigFileName          string            `env:"CONFIGURATION_FILE_NAME"`
	ServiceConfigUrl               string            `env:"CONFIGURATION_URL"`
	ProxyCacheTTL                  int               `env:"PROXY_CACHE_TTL" envDefault:"0"`
	AllowProxyOptimizer            bool              `env:"ALLOW_PROXY_OPTIMIZER" envDefault:"true"`
	DelayShutdownSeconds           int               `env:"DELAY_SHUTDOWN_SECONDS" envDefault:"10"`
	AdditionalHeadersToRedact      []string          `env:"ADDITIONAL_HEADERS_TO_REDACT"`
	HeaderBlockList                []string          `env:"HEADER_BLOCK_LIST"`
	HeadersToRemap                 map[string]string `env:"HEADERS_TO_REMAP" envSeparator:"," envKeyValSeparator:":"`
	ExposeManagementAPIs           bool              `env:"EXPOSE_MANAGEMENT_APIS" envDefault:"false"`
	DisableProxyCache              bool              `env:"DISABLE_PROXY_CACHE" envDefault:"false"`
	BasePathExtractorPrefixes      []string          `env:"BASE_PATH_MATCHERS"`
	DisallowedResponseContentTypes []string          `env:"DISALLOWED_RESPONSE_CONTENT_TYPE_LIST"`
	AllowedProxyTargetURLs         []string          `env:"ALLOWED_PROXY_TARGET_URLS" envSeparator:","`
	TokenPreemptiveExpirySeconds   int               `env:"TOKEN_PREEMPTIVE_EXPIRY_SECONDS" envDefault:"30"`
}

func GetEnvVariables() (EnvironmentVariables, error) {
	env, err := envlib.ParseAs[EnvironmentVariables]()
	if err != nil {
		return env, err
	}

	if (env.ServiceConfigPath == "" || env.ServiceConfigFileName == "") && env.ServiceConfigUrl == "" {
		return env, fmt.Errorf("required env variables not set")
	}
	if env.ServiceConfigPath != "" && env.ServiceConfigFileName != "" && env.ServiceConfigUrl != "" {
		return env, fmt.Errorf("cannot enable both dynamic and static configuration")
	}
	if len(env.ServicePrefix) > 0 {
		re := regexp.MustCompile(`^\/[a-zA-Z0-9_-]+$`)
		if !re.MatchString(env.ServicePrefix) {
			return env, fmt.Errorf("service prefix does not match the following regex: ^/[a-zA-Z0-9_-]+$")
		}
	}
	return env, nil
}

func (e EnvironmentVariables) IsStaticConfiguration() bool {
	return e.ServiceConfigPath != "" && e.ServiceConfigFileName != ""
}

func (e EnvironmentVariables) IsDynamicConfiguration() bool {
	return e.ServiceConfigUrl != ""
}

type ServiceConfig struct {
	Proxies []*entities.Proxy `json:"proxies" koanf:"proxies"`
}

func GetServiceConfigSchema() []byte {
	return []byte(configSchema)
}

func LoadServiceConfiguration(path, fileName string) (*ServiceConfig, error) {
	var config ServiceConfig
	err := configlib.GetConfigFromFile(fileName, path, GetServiceConfigSchema(), &config)
	if err != nil {
		return nil, err
	}
	for _, proxyConfiguration := range config.Proxies {
		pathParamsConfigIsCorrect, err := targetUrlAndBasePathContainSamePathParameters(proxyConfiguration)
		if !pathParamsConfigIsCorrect {
			return nil, err
		}
	}
	return &config, err
}

func targetUrlAndBasePathContainSamePathParameters(proxyConfiguration *entities.Proxy) (bool, error) {
	re := regexp.MustCompile(`{[a-zA-Z0-9_-]+}`)
	pathParameters := re.FindAllString(proxyConfiguration.TargetBaseUrl, -1)
	for _, pathParameter := range pathParameters {
		if !strings.Contains(proxyConfiguration.BasePath, pathParameter) {
			return false, fmt.Errorf("missing path parameters inside %v", proxyConfiguration.BasePath)
		}
	}
	return true, nil
}
