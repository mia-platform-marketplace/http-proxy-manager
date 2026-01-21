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
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	apihelpers "proxy-manager/apis/helpers"
	"proxy-manager/entities"
	"proxy-manager/internal/config"
	auth "proxy-manager/services/authentication"

	"github.com/sirupsen/logrus"
)

var (
	ErrInvalidUnsafeRedirect = errors.New("invalid unsafe redirect to a different URL schema source schema: HTTPS, target schema: HTTP")
)

// ProxyWithRetries creates a new HTTP request and retries it fi the status code is 401 or 403.
//
// Deprecated: function deprecated and to be removed with the ALLOW_PROXY_OPTIMIZER flag!
func ProxyWithRetries(
	logger *logrus.Entry,
	env config.EnvironmentVariables,
	req *http.Request,
	token string,
	proxy *entities.Proxy,
	tokensCache *auth.TokensCache,
) (status int, headers http.Header, body []byte, err error) {
	status, headers, body = makeRequest(logger, env, req, token, proxy)

	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		logTokenRelatedError(logger, proxy, tokensCache, true)

		tokensCache.DeleteCachedToken(proxy.TargetBaseUrl)
		token, err := tokensCache.GetAccessToken(logger, proxy)
		if err != nil {
			logger.WithError(err).Error("failed retrieving access token")
			return 0, nil, nil, err
		}
		status, headers, body = makeRequest(logger, env, req, token, proxy)
	}
	return
}

func makeRequest(logger *logrus.Entry, env config.EnvironmentVariables, req *http.Request, token string, proxy *entities.Proxy) (int, http.Header, []byte) {
	destinationUrl := retrieveUrl(logger, env, proxy, req)
	logger.WithField("destinationUrl", destinationUrl).Debug("destination URL of the request")

	client := http.Client{
		Timeout: time.Minute,
	}

	reqBody, err := io.ReadAll(req.Body)
	if err != nil {
		logger.WithError(err).Error("failed reading request body")
		return http.StatusInternalServerError, nil, nil
	}

	// The body of the original request is restored since it is read again on token expiration.
	req.Body = io.NopCloser(strings.NewReader(string(reqBody)))

	newReq, err := http.NewRequest(req.Method, destinationUrl, bytes.NewReader(reqBody))
	if err != nil {
		logger.WithError(err).Error("failed preparing request")
		return http.StatusInternalServerError, nil, nil
	}

	newReq.URL.RawQuery = req.URL.RawQuery

	opts := getHeadersOptions{
		HeadersToBlock: env.HeaderBlockList,
		HeadersToRemap: env.HeadersToRemap,
	}
	newReq.Header = getHeaders(proxy, token, req, opts)
	logger.WithFields(logrus.Fields{
		"RequestUrl":           newReq.URL,
		"RequestQuery":         newReq.URL.RawQuery,
		"RequestHeaders":       getRedactedHeaders(env, newReq.Header),
		"RequestContentLength": newReq.ContentLength,
		"RequestBody":          string(reqBody),
	}).Debug("request to forward prepared")

	res, err := client.Do(newReq)
	if err != nil {
		logger.
			WithError(err).
			WithField("destinationUrl", destinationUrl).
			Error("failed proxying request to the destination url")

		errorBytes := []byte{}
		if errors.Is(err, ErrInvalidUnsafeRedirect) {
			errorResponse := apihelpers.RequestError{
				Message: "failed proxying request to the destination url",
				Error:   ErrInvalidUnsafeRedirect.Error(),
			}

			errorBytes, err = json.Marshal(errorResponse)
			if err != nil {
				return http.StatusInternalServerError, nil, nil
			}
		}

		return http.StatusInternalServerError, nil, errorBytes
	}

	if err := checkContentTypeHeader(env, res.Header); err != nil {
		errMsg := "Content-Type of the target service response not allowed"
		logger.WithError(err).Error(errMsg)

		errorResponse := apihelpers.RequestError{
			Message: errMsg,
		}
		errorBytes, err := json.Marshal(errorResponse)
		if err != nil {
			return http.StatusInternalServerError, nil, nil
		}
		return http.StatusInternalServerError, nil, errorBytes
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		logger.WithError(err).Error("failed reading response body")
		return http.StatusInternalServerError, nil, nil
	}

	logger.WithFields(logrus.Fields{
		"responseStatusCode":    res.StatusCode,
		"responseStatus":        res.Status,
		"responseHeaders":       getRedactedHeaders(env, res.Header),
		"responseContentLength": res.ContentLength,
	}).Debug("response data")

	return res.StatusCode, res.Header, body
}
