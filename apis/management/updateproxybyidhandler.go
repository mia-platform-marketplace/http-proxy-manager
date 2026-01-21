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

	"github.com/gorilla/mux"
	glogrus "github.com/mia-platform/glogger/v4/loggers/logrus"
)

func UpdateProxyByIdHandler(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	logger := glogrus.FromContext(ctx)

	proxyId := mux.Vars(req)["id"]
	if proxyId == "" {
		message := "missing id path parameter"
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

	updatedProxy, err := proxyservice.UpdateProxyById(ctx, crudClient, proxyId, fieldsToUpdate)
	if err != nil {
		message := "failed to update proxy"
		if errors.Is(err, proxyservice.ErrInvalidPatchRequest) {
			apihelpers.WriteErrorResponse(w, logger, err, message, http.StatusBadRequest)
			return
		}
		apihelpers.WriteErrorResponse(w, logger, err, message, http.StatusInternalServerError)
		return
	}

	filteredResponse := adaptProxyToItemResponse(updatedProxy)

	apihelpers.WriteJSONResponse(w, 200, nil, filteredResponse)
}
