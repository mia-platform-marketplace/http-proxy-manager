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
	"net/url"
	"strings"

	"proxy-manager/entities"
	"proxy-manager/internal/config"
	"proxy-manager/internal/pathextractor"

	"github.com/sirupsen/logrus"
)

func extractBasePath(originalPath string, graph *pathextractor.Node) string {
	if graph == nil {
		// Dynamic configuration has the limitation of using just the first path component as basePath, that's why we use pathComponents[1]
		pathComponents := strings.Split(originalPath, "/")
		return "/" + pathComponents[1]
	}

	return pathextractor.BuildBasePath(graph, originalPath)
}

func removeBasePathFromTargetUrl(path string, basePath string) string {
	path = strings.TrimPrefix(path, "/")
	basePath = strings.TrimPrefix(basePath, "/")
	path = strings.TrimPrefix(path, basePath)
	path = strings.TrimPrefix(path, "/")
	return path
}

func findAndReplacePathParameters(proxy *entities.Proxy, path string) (string, string, string) {
	basePath := proxy.BasePath
	targetBaseUrl := proxy.TargetBaseUrl
	splittedPath := strings.Split(path, "/")
	splittedBasePath := strings.Split(basePath, "/")

	for index, pathSegment := range splittedBasePath {
		if strings.HasPrefix(pathSegment, "{") && strings.HasSuffix(pathSegment, "}") {
			pathValue := splittedPath[index]
			basePath = strings.Replace(basePath, pathSegment, pathValue, 1)
			targetBaseUrl = strings.Replace(targetBaseUrl, pathSegment, pathValue, 1)
		}
	}

	return path, basePath, targetBaseUrl
}

// finalizeTargetBaseURL tries to concat the target base url with the final path
// to proxy. The function prevents `//` to occurr when joining the two parts.
// TODO: the implementation could be easily exchanged with
// url.JoinPath(targetBaseURL, pathToProxy)`, however `url.JoinPath` returns an
// error if the provided baseurl is not parseable. Such error would need
// propagation all the way up to the handler.
func finalizeTargetBaseURL(targetBaseURL string, pathToProxy string) string {
	if pathToProxy == "" {
		return targetBaseURL
	}

	baseUrlToJoin := targetBaseURL
	if !strings.HasSuffix(targetBaseURL, "/") && !strings.HasPrefix(pathToProxy, "/") {
		baseUrlToJoin += "/"
	}

	finalPath := pathToProxy
	if strings.HasSuffix(targetBaseURL, "/") && strings.HasPrefix(pathToProxy, "/") {
		finalPath = strings.TrimPrefix(pathToProxy, "/")
	}
	return fmt.Sprintf("%s%s", baseUrlToJoin, finalPath)
}

func retrieveUrl(
	_ *logrus.Entry,
	env config.EnvironmentVariables,
	proxy *entities.Proxy,
	req *http.Request,
) string {
	url, _ := url.Parse(req.RequestURI)
	path := url.Path

	if env.ServicePrefix != "" && env.ServicePrefix != "/" {
		path = strings.TrimPrefix(path, env.ServicePrefix)
	}

	if env.IsDynamicConfiguration() {
		pathToProxy := strings.TrimPrefix(path, proxy.BasePath)

		// NOTE: I'm 90% sure the following code block is useless as I'd expect
		// trimming the basePath property is more than enough instead of trimming
		// the first path segment. However there were previous tests that were
		// ensuring the first segment were truncated regardless of its value (where
		// it differs from the actual proxy.basePath).
		// I'm pretty confident those tests data are drunk, however I don't want to
		// cause any possible breaking change, so this code is here to preserve the
		// expected behaviour from tests. ¯\_(ツ)_/¯
		if len(env.BasePathExtractorPrefixes) == 0 {
			path = strings.TrimPrefix(path, "/")
			pathToProxy = "/" + strings.Join(strings.Split(path, "/")[1:], "/")
		}

		return finalizeTargetBaseURL(proxy.TargetBaseUrl, pathToProxy)
	}

	path, basePath, targetBaseUrl := findAndReplacePathParameters(proxy, path)
	pathToProxy := removeBasePathFromTargetUrl(path, basePath)
	return finalizeTargetBaseURL(targetBaseUrl, pathToProxy)
}
