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

package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxy-manager/entities"

	"github.com/sirupsen/logrus"
)

const accessTokenContentType = "application/x-www-form-urlencoded"

const authorizationHeaderBearerFormat = "Bearer %s"

type AccessToken struct {
	AccessToken string          `json:"access_token"`
	ExpiresIn   json.RawMessage `json:"expires_in"`
	Scope       string          `json:"scope"`
	TokenType   string          `json:"token_type"`
	ExpiresAt   time.Time       `json:"expires_at,omitempty"`
}

type TokensCache struct {
	cache                        map[string]AccessToken
	lock                         sync.Mutex
	tokenPreemptiveExpirySeconds int
}

func NewTokensCache(tokenPreemptiveExpirySeconds int) *TokensCache {
	return &TokensCache{
		cache:                        make(map[string]AccessToken),
		lock:                         sync.Mutex{},
		tokenPreemptiveExpirySeconds: tokenPreemptiveExpirySeconds,
	}
}

func (t *TokensCache) GetCachedToken(url string) (AccessToken, bool) {
	t.lock.Lock()
	token, ok := t.cache[url]
	t.lock.Unlock()

	return token, ok
}

func (t *TokensCache) SetCachedToken(url string, accessToken AccessToken) {
	t.lock.Lock()
	t.cache[url] = accessToken
	t.lock.Unlock()
}

func (t *TokensCache) DeleteCachedToken(url string) {
	t.lock.Lock()
	delete(t.cache, url)
	t.lock.Unlock()
}

func (t *TokensCache) validateCachedToken(token AccessToken, _ *logrus.Entry, proxy *entities.Proxy) (bool, error) {

	req, err := http.NewRequest(http.MethodGet, proxy.TokenIssuerValidationUrl, nil)
	req.Header.Add("Authorization", fmt.Sprintf(authorizationHeaderBearerFormat, token.AccessToken))
	if err != nil {
		return false, fmt.Errorf("failed request creation: %s", err.Error())
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed token validation request: %s", err.Error())
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return false, nil
	}

	return true, nil
}

func (t *TokensCache) GetAccessToken(logger *logrus.Entry, proxy *entities.Proxy) (string, error) {
	token, ok := t.GetCachedToken(proxy.TargetBaseUrl)
	if !ok {
		logger.Info("token not found in local cache")
		newToken, err := t.requestAccessToken(logger, proxy)
		if err != nil {
			return "", err
		}
		return newToken.AccessToken, nil
	}

	if t.isTokenExpired(&token) {
		logger.Info("token found in local cache but it is expired")
		newToken, err := t.requestAccessToken(logger, proxy)
		if err != nil {
			return "", err
		}
		return newToken.AccessToken, nil
	}

	if proxy.TokenIssuerValidationUrl == "" {
		return token.AccessToken, nil
	}
	valid, err := t.validateCachedToken(token, logger, proxy)
	if err != nil {
		return "", fmt.Errorf("failed token validation: %s", err.Error())
	}

	if valid {
		return token.AccessToken, nil
	}

	newToken, err := t.requestAccessToken(logger, proxy)
	if err != nil {
		return "", err
	}
	return newToken.AccessToken, nil
}

func (t *TokensCache) requestAccessToken(logger *logrus.Entry, proxy *entities.Proxy) (AccessToken, error) {
	data := url.Values{}
	data.Set("grant_type", proxy.GrantType)

	if proxy.GrantType == "password" {
		data.Set("username", proxy.Username)
		data.Set("password", proxy.Password)
		data.Set("client_id", proxy.ClientId)
		data.Set("client_secret", proxy.ClientSecret)
	}

	for field, value := range proxy.AdditionalAuthFields {
		data.Set(field, value)
	}

	body := strings.NewReader(data.Encode())
	logger.WithField("tokenIssuerURL", proxy.TokenIssuerUrl).Info("requesting new access token from token issuer")
	req, err := http.NewRequest(http.MethodPost, proxy.TokenIssuerUrl, body)
	if err != nil {
		return AccessToken{}, fmt.Errorf("failed request creation: %s", err.Error())
	}
	req.Header.Add("content-type", accessTokenContentType)

	switch proxy.AuthType {
	case "client_secret_basic":
		{
			req.SetBasicAuth(proxy.ClientId, proxy.ClientSecret)
		}
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return AccessToken{}, fmt.Errorf("failed token request: %s", err.Error())
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return AccessToken{}, fmt.Errorf("unexpected status code on token request: %d", res.StatusCode)
	}

	responseBodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return AccessToken{}, fmt.Errorf("failed token response read: %s", err.Error())
	}
	accessToken := AccessToken{}
	if err := json.Unmarshal(responseBodyBytes, &accessToken); err != nil {
		return accessToken, fmt.Errorf("failed token response unmarshal: %s", err.Error())
	}

	expiresIn, err := unmarshalExpiresIn(accessToken)
	if err != nil {
		return accessToken, err
	}

	accessToken.ExpiresAt = time.Now().UTC().Add(time.Second * time.Duration(expiresIn))

	t.SetCachedToken(proxy.TargetBaseUrl, accessToken)
	logger.WithFields(logrus.Fields{
		"tokenExpiration": accessToken.ExpiresAt,
		"targetUrl":       proxy.TargetBaseUrl,
	}).Debug("successfully retrieved access token from token issuer")

	return accessToken, nil
}

func unmarshalExpiresIn(accessToken AccessToken) (int, error) {
	var expiresIn int
	if err := json.Unmarshal(accessToken.ExpiresIn, &expiresIn); err != nil {
		var expiresInAsString string
		if err := json.Unmarshal(accessToken.ExpiresIn, &expiresInAsString); err != nil {
			return 0, fmt.Errorf("failed to unmarshal expires_in: %s", err.Error())
		}
		expiresIn, err = strconv.Atoi(expiresInAsString)
		if err != nil {
			return 0, fmt.Errorf("failed to convert expires_in from string to int: %s", err.Error())
		}
	}
	return expiresIn, nil
}

func (t *TokensCache) isTokenExpired(token *AccessToken) bool {
	time0Value := time.Time{}
	if time0Value.Equal(token.ExpiresAt) {
		return false
	}
	// Preemptively consider the token expired tokenPreemptiveExpirySeconds before actual expiration
	// to avoid race conditions where the token expires between validation and usage.
	// For example, with a 30-second preemptive expiry, a token expiring at 12:00:30 will be
	// considered expired at 12:00:00, forcing a refresh and preventing 401 errors.
	preemptiveExpiryTime := time.Now().UTC().Add(time.Duration(t.tokenPreemptiveExpirySeconds) * time.Second)
	return preemptiveExpiryTime.After(token.ExpiresAt)
}
