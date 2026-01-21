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

package proxies

import (
	"encoding/json"
	"fmt"

	"proxy-manager/internal/config"

	"github.com/xeipuuv/gojsonschema"
)

func buildJsonConfig(proxies []byte) []byte {
	jsonConfig := append([]byte(`{"proxies": `), proxies...)
	return append(jsonConfig, []byte(`}`)...)
}

func validateProxiesSchema(jsonSchema []byte, proxies []byte) error {
	jsonConfig := buildJsonConfig(proxies)
	schemaLoader := gojsonschema.NewBytesLoader(jsonSchema)
	documentLoader := gojsonschema.NewBytesLoader(jsonConfig)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("error validating: %s", err.Error())
	}
	if !result.Valid() {
		return fmt.Errorf("json schema validation errors: %s", result.Errors())
	}
	return nil
}

func ValidateProxy(proxy CrudProxy) error {
	proxies := make([]CrudProxy, 0)
	proxies = append(proxies, proxy)

	proxyBytes, err := json.Marshal(proxies)
	if err != nil {
		return err
	}

	return validateProxiesSchema(config.GetServiceConfigSchema(), proxyBytes)
}
