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

package management

import (
	"math"
	"net/http"
	"strings"

	apihelpers "proxy-manager/apis/helpers"
	"proxy-manager/apis/middlewares"
	proxyservice "proxy-manager/services/proxies"

	glogrus "github.com/mia-platform/glogger/v4/loggers/logrus"
)

type ProxyItemResponse struct {
	BasePath                 string   `json:"basePath"`
	TargetBaseUrl            string   `json:"targetBaseUrl"`
	Authentication           *string  `json:"authentication,omitempty"`
	Username                 *string  `json:"username,omitempty"`
	ClientId                 *string  `json:"clientId,omitempty"`
	GrantType                *string  `json:"grantType,omitempty"`
	AuthType                 *string  `json:"authType,omitempty"`
	TokenIssuerURL           *string  `json:"tokenIssuerUrl,omitempty"`
	TokenIssuerValidationUrl *string  `json:"tokenIssuerValidationUrl,omitempty"`
	HeadersToProxy           []string `json:"headersToProxy,omitempty"`
}

type ProxyListResponse = []ProxyItemResponse

func GetProxiesHandler(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	logger := glogrus.FromContext(ctx)

	basePathQuery := req.URL.Query().Get("basePath")
	page, perPage, err := apihelpers.GetPaginationFromQuery(req.URL.Query())
	if err != nil {
		message := "invalid pagination query parameters"
		apihelpers.WriteErrorResponse(w, logger, err, message, http.StatusBadRequest)
		return
	}

	crudClient, err := middlewares.ResolveCrudClient[proxyservice.CrudProxy](ctx)
	if err != nil {
		message := "failed to resolve proxies crud client"
		apihelpers.WriteErrorResponse(w, logger, err, message, http.StatusInternalServerError)
		return
	}

	filterProxiesOptions := proxyservice.FilterProxiesOptions{}

	if basePathQuery != "" {
		splittedBasePaths := strings.Split(basePathQuery, ",")
		if len(splittedBasePaths) > 1 {
			filterProxiesOptions.BasePathList = splittedBasePaths
		} else {
			filterProxiesOptions.BasePath = &basePathQuery
		}
	}

	proxiesCount, err := proxyservice.CountProxies(ctx, crudClient, filterProxiesOptions)
	if err != nil {
		message := "failed to retrieve proxies count"
		apihelpers.WriteErrorResponse(w, logger, err, message, http.StatusInternalServerError)
		return
	}

	filterProxiesOptions.Page = page
	filterProxiesOptions.PerPage = perPage

	proxies, err := proxyservice.GetProxies(ctx, crudClient, filterProxiesOptions)
	if err != nil {
		message := "failed to retrieve proxy"
		apihelpers.WriteErrorResponse(w, logger, err, message, http.StatusInternalServerError)
		return
	}

	pagesCount := int(math.Ceil(float64(proxiesCount) / float64(*perPage)))

	body := mapResponse(proxies)
	apihelpers.SetPaginationHeaders(w, pagesCount, proxiesCount)
	apihelpers.WriteJSONResponse(w, 200, nil, body)
}

func mapResponse(proxies []proxyservice.CrudProxy) ProxyListResponse {
	responseProxies := make([]ProxyItemResponse, 0)

	for _, proxy := range proxies {
		responseProxies = append(responseProxies, adaptProxyToItemResponse(&proxy))
	}

	return responseProxies
}

func adaptProxyToItemResponse(proxy *proxyservice.CrudProxy) ProxyItemResponse {
	return ProxyItemResponse{
		BasePath:                 proxy.BasePath,
		TargetBaseUrl:            proxy.TargetBaseUrl,
		Authentication:           proxy.Authentication,
		AuthType:                 proxy.AuthType,
		Username:                 proxy.Username,
		ClientId:                 proxy.ClientId,
		GrantType:                proxy.GrantType,
		HeadersToProxy:           proxy.HeadersToProxy,
		TokenIssuerURL:           proxy.TokenIssuerUrl,
		TokenIssuerValidationUrl: proxy.TokenIssuerValidationUrl,
	}
}
