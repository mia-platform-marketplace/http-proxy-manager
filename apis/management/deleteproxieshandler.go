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
	"fmt"
	"net/http"

	apihelpers "proxy-manager/apis/helpers"
	"proxy-manager/apis/middlewares"
	proxyservice "proxy-manager/services/proxies"

	glogrus "github.com/mia-platform/glogger/v4/loggers/logrus"
)

func DeleteProxiesHandler(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	logger := glogrus.FromContext(ctx)

	basePath := req.URL.Query().Get("basePath")
	basePathPrefix := req.URL.Query().Get("basePathPrefix")

	if (basePath != "" && basePathPrefix != "") || (basePath == "" && basePathPrefix == "") {
		message := "exactly one between basePath and basePathPrefix must be specified"
		err := fmt.Errorf("%s", message)
		apihelpers.WriteErrorResponse(w, logger, err, message, http.StatusBadRequest)
		return
	}

	crudClient, err := middlewares.ResolveCrudClient[proxyservice.CrudProxy](ctx)
	if err != nil {
		message := "failed to resolve proxies crud client"
		apihelpers.WriteErrorResponse(w, logger, err, message, http.StatusInternalServerError)
		return
	}

	if basePath != "" {
		_, err = proxyservice.DeleteProxyByBasePath(ctx, crudClient, basePath)
	} else if basePathPrefix != "" {
		_, err = proxyservice.DeleteProxiesMatchingPrefix(ctx, crudClient, basePathPrefix)
	}

	if err != nil {
		message := "failed to delete proxies"
		apihelpers.WriteErrorResponse(w, logger, err, message, http.StatusInternalServerError)
		return
	}

	apihelpers.WriteJSONResponse(w, http.StatusNoContent, nil, nil)
}
