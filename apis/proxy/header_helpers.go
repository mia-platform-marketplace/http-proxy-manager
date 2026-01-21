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
	"fmt"
	"net/http"
	"strings"

	"proxy-manager/entities"
	"proxy-manager/internal/config"
)

type getHeadersOptions struct {
	HeadersToBlock []string
	HeadersToRemap map[string]string
}

func getHeaders(proxy *entities.Proxy, token string, req *http.Request, options getHeadersOptions) http.Header {
	headers := http.Header{}
	if proxy.HeadersToProxy == nil {
		// forward all the headers
		for name, values := range req.Header {
			for _, value := range values {
				headers.Add(name, value)
			}
		}
	} else {
		// forward only selected headers
		for _, header := range proxy.HeadersToProxy {
			for _, value := range req.Header.Values(header) {
				headers.Add(header, value)
			}
		}
	}

	if token != "" {
		headers.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	if proxy.AdditionalHeaders != nil {
		for _, header := range proxy.AdditionalHeaders {
			headers.Add(header.Name, header.Value)
		}
	}

	if len(options.HeadersToRemap) > 0 {
		for remapFrom, remapTo := range options.HeadersToRemap {
			headerVal := req.Header.Get(remapFrom)
			if headerVal != "" {
				headers.Del(remapFrom)
				headers.Set(remapTo, headerVal)
			}
		}
	}

	if len(options.HeadersToBlock) > 0 {
		for _, header := range options.HeadersToBlock {
			headers.Del(header)
		}
	}

	return headers
}

func getRedactedHeaders(env config.EnvironmentVariables, headers http.Header) http.Header {
	defaultHeadersToRedact := []string{"Authorization", "Cookie", "Proxy-Authorization", "Set-Cookie", "Www-Authenticate"}
	headersToRedact := append(defaultHeadersToRedact, env.AdditionalHeadersToRedact...)
	redactedHeaders := headers.Clone()
	for _, headerToRedact := range headersToRedact {
		if redactedHeaders.Get(headerToRedact) != "" {
			redactedHeaders.Set(headerToRedact, "[REDACTED]")
		}
	}
	return redactedHeaders
}

func checkContentTypeHeader(env config.EnvironmentVariables, headers http.Header) error {
	contentTypeHeader := headers.Get("Content-Type")
	for _, disallowedContentType := range env.DisallowedResponseContentTypes {
		if strings.Contains(strings.ToLower(contentTypeHeader), strings.ToLower(disallowedContentType)) {
			return fmt.Errorf("Content-Type header with value %s not accepted", contentTypeHeader)
		}
	}
	return nil
}
