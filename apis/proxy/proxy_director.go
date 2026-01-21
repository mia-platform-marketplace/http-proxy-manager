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

package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	apihelpers "proxy-manager/apis/helpers"
	"proxy-manager/entities"
	"proxy-manager/internal/config"
	auth "proxy-manager/services/authentication"

	"github.com/sirupsen/logrus"
)

func ProxyDirector(logger *logrus.Entry, env config.EnvironmentVariables, token string, proxy *entities.Proxy) func(*http.Request) {
	headersToProxyMap := http.Header{}
	for _, header := range proxy.HeadersToProxy {
		headersToProxyMap.Set(header, "allowed")
	}
	return func(req *http.Request) {
		logger.WithField("requestURI", req.RequestURI).Info("handling request")
		destinationUrl := retrieveUrl(logger, env, proxy, req)

		newURL, err := url.Parse(destinationUrl)

		queryParameters := req.URL.RawQuery

		// In order to correctly proxy the request is needed to set the req.Host to the one we are interested to not make it equal to the requesting host
		req.Host = newURL.Host
		req.URL = newURL
		req.URL.RawQuery = queryParameters

		if err != nil {
			logger.WithError(err).Error("failed parsing destination URL")
			return
		}

		opts := getHeadersOptions{
			HeadersToBlock: env.HeaderBlockList,
			HeadersToRemap: env.HeadersToRemap,
		}
		req.Header = getHeaders(proxy, token, req, opts)
		if _, ok := req.Header["User-Agent"]; !ok {
			// Explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}

		if headersToProxyMap.Get("X-Forwarded-For") == "" {
			// Explicitly disable X-Forwarded-For header to preserve compatibility with not optimized
			req.Header.Set("X-Forwarded-For", "")
		}

		logger.WithFields(logrus.Fields{
			"RequestUrl":           req.URL,
			"RequestHeaders":       getRedactedHeaders(env, req.Header),
			"RequestContentLength": req.ContentLength,
		}).Debug("request to forward prepared")
	}
}

func getResponseModifier(logger *logrus.Entry, proxy *entities.Proxy, tokensCache *auth.TokensCache, env config.EnvironmentVariables) func(*http.Response) error {
	return func(r *http.Response) error {
		if r.StatusCode == http.StatusUnauthorized || r.StatusCode == http.StatusForbidden {
			logTokenRelatedError(logger, proxy, tokensCache, false)
			tokensCache.DeleteCachedToken(proxy.TargetBaseUrl)
		}

		if err := checkContentTypeHeader(env, r.Header); err != nil {
			errMsg := "Content-Type of the target service response not allowed"
			logger.WithError(err).Error(errMsg)

			r.StatusCode = http.StatusInternalServerError

			errorResponse := apihelpers.RequestError{
				Message: errMsg,
			}
			errorBytes, err := json.Marshal(errorResponse)
			if err != nil {
				return nil
			}

			r.Body = io.NopCloser(bytes.NewReader(errorBytes))
		}

		return nil
	}
}
