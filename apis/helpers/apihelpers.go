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

package apihelpers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/sirupsen/logrus"
)

type RequestError struct {
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

const (
	TotalPagesHeaderKey = "x-total-pages"
	TotalItemsHeaderKey = "x-total-items"
	DefaultPageValue    = 1
	DefaultPerPageValue = 25
)

func WriteResponse(w http.ResponseWriter, statusCode int, headers http.Header, body []byte) {
	for name, values := range headers {
		for _, value := range values {
			w.Header().Set(name, value)
		}
	}
	w.WriteHeader(statusCode)
	w.Write(body)
}

func WriteJSONResponse(w http.ResponseWriter, statusCode int, headers http.Header, body interface{}) {
	if headers == nil {
		headers = http.Header{}
	}

	responseBytes, err := json.Marshal(body)

	if err != nil {
		statusCode = http.StatusInternalServerError
		WriteResponse(w, statusCode, headers, []byte(err.Error()))
		return
	}

	headers.Set("Content-Type", "application/json")
	WriteResponse(w, statusCode, headers, responseBytes)
}

func WriteErrorResponse(w http.ResponseWriter, logger *logrus.Entry, err error, message string, httpStatus int) {
	logger.WithField("error", logrus.Fields{"message": err.Error()}).Error(message)
	errorResponse := RequestError{
		Message: message,
		Error:   err.Error(),
	}
	WriteJSONResponse(w, httpStatus, http.Header{}, errorResponse)
}

func SetPaginationHeaders(w http.ResponseWriter, pagesCount int, itemsCount int) {
	w.Header().Set(TotalPagesHeaderKey, fmt.Sprintf("%d", pagesCount))
	w.Header().Set(TotalItemsHeaderKey, fmt.Sprintf("%d", itemsCount))
}

func GetPaginationFromQuery(query url.Values) (*int, *int, error) {
	var err error
	page := DefaultPageValue
	perPage := DefaultPerPageValue

	pageQuery := query.Get("page")
	perPageQuery := query.Get("per_page")

	if pageQuery != "" {
		if page, err = strconv.Atoi(pageQuery); err != nil || page <= 0 {
			return nil, nil, fmt.Errorf("invalid page value %s", pageQuery)
		}
	}

	if perPageQuery != "" {
		if perPage, err = strconv.Atoi(perPageQuery); err != nil || perPage <= 0 {
			return nil, nil, fmt.Errorf("invalid per_page value %s", perPageQuery)
		}
	}

	return &page, &perPage, nil
}
