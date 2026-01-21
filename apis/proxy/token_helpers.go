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
	"time"

	"proxy-manager/entities"
	auth "proxy-manager/services/authentication"

	"github.com/sirupsen/logrus"
)

// This method is used for accurate logging purposes
func isTokenActuallyExpired(token *auth.AccessToken) bool {
	return (token.ExpiresAt != time.Time{}) && time.Now().UTC().After(token.ExpiresAt)
}

func logTokenRelatedError(logger *logrus.Entry, proxy *entities.Proxy, tokensCache *auth.TokensCache, includeRetryMessage bool) {
	baseURL := proxy.TargetBaseUrl
	retryMsg := ""
	if includeRetryMessage {
		retryMsg = ", retrying with new token"
	} else {
		retryMsg = ", clearing token cache"
	}

	if cachedToken, ok := tokensCache.GetCachedToken(baseURL); ok {
		if isTokenActuallyExpired(&cachedToken) {
			logger.WithField("targetBaseURL", baseURL).Warn("token expired" + retryMsg)
		} else {
			logger.WithField("targetBaseURL", baseURL).Warn("received 401/403 response" + retryMsg + " (cached token may not be expired)")
		}
	} else {
		logger.WithField("targetBaseURL", baseURL).Warn("received 401/403 response" + retryMsg + " (no cached token found)")
	}
}
