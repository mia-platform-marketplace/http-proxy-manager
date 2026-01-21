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

package allowedtargets

import (
	"fmt"
	"net/url"

	repository "proxy-manager/repositories/allowedtargets"
)

var (
	ErrNotAllowedTargetURL = fmt.Errorf("specified target URL is not allowed")
)

type service struct {
	repository repository.IAllowedTargetsRepository
}

func New(
	repository repository.IAllowedTargetsRepository,
) IService {
	return &service{
		repository: repository,
	}
}

func (s service) AssertTargetAllowed(targetBaseURL string) error {
	if s.repository.CountAll() == 0 {
		return nil
	}

	targetURL, err := url.Parse(targetBaseURL)
	if err != nil {
		return err
	}

	remoteBaseURL := fmt.Sprintf("%s://%s", targetURL.Scheme, targetURL.Host)
	matchingURL := s.repository.FindOne(remoteBaseURL)
	if matchingURL == nil {
		return ErrNotAllowedTargetURL
	}

	return nil
}
