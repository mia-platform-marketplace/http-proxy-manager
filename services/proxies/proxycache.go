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

package proxies

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"proxy-manager/entities"
	"proxy-manager/internal/config"
)

type ProxyCache map[string]ProxyCacheItem

type ProxyCacheItem struct {
	Expiration int64
	Proxy      entities.Proxy
}

func (p *ProxyCacheItem) IsExpired() bool {
	return time.Now().After(time.Unix(p.Expiration, 0))
}

func computeExpiration(proxyCacheTTL int) int64 {
	return time.Now().Add(time.Duration(proxyCacheTTL) * time.Second).Unix()
}

func fetchAndValidateProxies(proxiesUrl string) ([]byte, error) {
	crudResponse, err := http.Get(proxiesUrl)
	if err != nil {
		return nil, err
	}
	if crudResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRUD replied with status code %v", crudResponse.StatusCode)
	}
	proxies, err := io.ReadAll(crudResponse.Body)
	if err != nil {
		return nil, err
	}
	if err = validateProxiesSchema(config.GetServiceConfigSchema(), proxies); err != nil {
		return nil, err
	}
	return proxies, nil
}

func FetchProxy(serviceConfigUrl string, basePath string) (*entities.Proxy, error) {
	proxiesUrl, err := url.Parse(serviceConfigUrl)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set("basePath", basePath)
	proxiesUrl.RawQuery = query.Encode()

	proxies, err := fetchAndValidateProxies(proxiesUrl.String())
	if err != nil {
		return nil, err
	}

	var proxiesSlice []entities.Proxy
	if err = json.Unmarshal(proxies, &proxiesSlice); err != nil {
		return nil, err
	}
	if len(proxiesSlice) == 0 {
		return nil, fmt.Errorf("proxy not found")
	}

	return &proxiesSlice[0], nil
}

func FetchAndUpdateProxyCache(serviceConfigUrl string, basePath string, proxiesCache *ProxyCache, proxyCacheTTL int) error {
	proxy, err := FetchProxy(serviceConfigUrl, basePath)
	if err != nil {
		return err
	}

	(*proxiesCache)[basePath] = ProxyCacheItem{
		Expiration: computeExpiration(proxyCacheTTL),
		Proxy:      *proxy,
	}
	return nil
}
