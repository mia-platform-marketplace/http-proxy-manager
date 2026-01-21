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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	apihelpers "proxy-manager/apis/helpers"
	"proxy-manager/apis/middlewares"
	proxyservice "proxy-manager/services/proxies"

	glogrus "github.com/mia-platform/glogger/v4/loggers/logrus"
)

type UpdateProxyByBasePathResponse struct {
	Count int `json:"count"`
}

func UpdateProxyByBasePathHandler(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	logger := glogrus.FromContext(ctx)

	basePath := req.URL.Query().Get("basePath")
	if basePath == "" {
		message := "missing basePath query parameter"
		err := fmt.Errorf("%s", message)
		apihelpers.WriteErrorResponse(w, logger, err, message, http.StatusBadRequest)
		return
	}

	var fieldsToUpdate map[string]interface{}
	if err := json.NewDecoder(req.Body).Decode(&fieldsToUpdate); err != nil {
		message := "failed request body deserialization"
		apihelpers.WriteErrorResponse(w, logger, err, message, http.StatusBadRequest)
		return
	}

	crudClient, err := middlewares.ResolveCrudClient[proxyservice.CrudProxy](ctx)
	if err != nil {
		message := "failed to resolve proxies crud client"
		apihelpers.WriteErrorResponse(w, logger, err, message, http.StatusInternalServerError)
		return
	}

	count, err := proxyservice.UpdateProxyByBasePath(ctx, crudClient, basePath, fieldsToUpdate)
	if err != nil {
		message := "failed to update proxy"
		if errors.Is(err, proxyservice.ErrInvalidPatchRequest) {
			apihelpers.WriteErrorResponse(w, logger, err, message, http.StatusBadRequest)
			return
		}
		apihelpers.WriteErrorResponse(w, logger, err, message, http.StatusInternalServerError)
		return
	}

	response := UpdateProxyByBasePathResponse{
		Count: count,
	}

	apihelpers.WriteJSONResponse(w, 200, nil, response)
}
