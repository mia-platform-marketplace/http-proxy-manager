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
	"context"
	"errors"
	"fmt"

	"proxy-manager/internal/mongohelpers"
	"proxy-manager/services/allowedtargets"

	"github.com/mia-platform/go-crud-service-client"
)

var (
	ErrInvalidPatchRequest = errors.New("invalid patch request")

	ErrPatchInputAuthNoneWithCredentials    = errors.New("can't provide authentication data when authentication is set to none")
	ErrPatchInputMissingGrantTypeForOauth2  = errors.New("missing grant_type while requiring authentication")
	ErrPatchInputMissingPasswordCredentials = errors.New("missing username or password in patch request specifying password grant_type")
	ErrPatchInputMissingClientCredentials   = errors.New("missing clientId or clientSecret in patch request specifying client_credentials grant_type")
	ErrPatchInputInvalidAuthType            = errors.New("invalid authType provided")
	ErrPatchInputInvalidAuthentication      = errors.New("invalid authentication provided")
)

func CreateProxy(
	ctx context.Context,
	crudClient crud.CrudClient[CrudProxy],
	proxy CrudProxy,
) (string, error) {
	if err := assertAllowedTargetBaseURL(ctx, proxy.TargetBaseUrl); err != nil {
		return "", err
	}

	return crudClient.Create(ctx, proxy, crud.Options{})
}

func hasField(fields map[string]any, fieldName string) bool {
	_, ok := fields[fieldName]
	return ok
}

func validatePatchInput(fieldsToUpdate map[string]any) error {
	hasField := func(fieldName string) bool {
		return hasField(fieldsToUpdate, fieldName)
	}
	missingField := func(fieldName string) bool {
		return !hasField(fieldName)
	}

	if hasField("authentication") && fieldsToUpdate["authentication"] != nil &&
		fieldsToUpdate["authentication"] != AuthenticationModeNone &&
		fieldsToUpdate["authentication"] != AuthenticationModeOauth2 {
		return ErrPatchInputInvalidAuthentication
	}

	if fieldsToUpdate["authentication"] == AuthenticationModeOauth2 && missingField("grantType") {
		return ErrPatchInputMissingGrantTypeForOauth2
	}

	if fieldsToUpdate["authentication"] == AuthenticationModeNone &&
		(hasField("grantType") ||
			hasField("username") ||
			hasField("password") ||
			hasField("clientId") ||
			hasField("clientSecret") ||
			hasField("authType") ||
			hasField("tokenIssuerUrl") ||
			hasField("tokenIssuerValidationUrl")) {
		return ErrPatchInputAuthNoneWithCredentials
	}

	if fieldsToUpdate["grantType"] == GrantTypePassword &&
		(missingField("username") || missingField("password")) {
		return ErrPatchInputMissingPasswordCredentials
	}
	if fieldsToUpdate["grantType"] == GrantTypeClientCredentials &&
		(missingField("clientId") || missingField("clientSecret")) {
		return ErrPatchInputMissingClientCredentials
	}

	if hasField("authType") && fieldsToUpdate["authType"] != ClientCredentialsAuthTypeBasic {
		return ErrPatchInputInvalidAuthType
	}

	return nil
}

func getAuthnFieldToForciblyUnset(fieldsToUpdate map[string]any) map[string]bool {
	fieldsToUnset := make(map[string]bool)

	unsetCommonAuthnBasedFields := func() {
		fieldsToUnset["tokenIssuerUrl"] = true
		fieldsToUnset["tokenIssuerValidationUrl"] = true
		fieldsToUnset["grantType"] = true
	}
	unsetPasswordBasedFields := func() {
		fieldsToUnset["username"] = true
		fieldsToUnset["password"] = true
	}
	unsetCCBasedFields := func() {
		fieldsToUnset["clientId"] = true
		fieldsToUnset["clientSecret"] = true
		fieldsToUnset["authType"] = true
	}

	if fieldsToUpdate["authentication"] == AuthenticationModeNone {
		unsetCommonAuthnBasedFields()
		unsetPasswordBasedFields()
		unsetCCBasedFields()
	}

	if fieldsToUpdate["grantType"] == GrantTypePassword {
		unsetCCBasedFields()
	}

	if fieldsToUpdate["grantType"] == GrantTypeClientCredentials {
		unsetPasswordBasedFields()
	}
	return fieldsToUnset
}

func generateCRUDPatchBody(fieldsToUpdate map[string]any) crud.PatchBody {
	fieldsToSet := make(map[string]any)
	fieldsToUnset := make(map[string]bool)

	for key, value := range fieldsToUpdate {
		if value == nil {
			fieldsToUnset[key] = true
		} else {
			fieldsToSet[key] = value
		}
	}

	authnFieldsToUnset := getAuthnFieldToForciblyUnset(fieldsToUpdate)
	for k, v := range authnFieldsToUnset {
		fieldsToUnset[k] = v
	}

	return crud.PatchBody{
		Set:   fieldsToSet,
		Unset: fieldsToUnset,
	}
}

func assertAllowedTargetBaseURL(ctx context.Context, targetBaseURL string) error {
	allowedTargetsService, err := allowedtargets.Resolve(ctx)
	if err != nil {
		return err
	}

	if err := allowedTargetsService.AssertTargetAllowed(targetBaseURL); err != nil {
		return err
	}

	return nil
}

func UpdateProxyById(
	ctx context.Context,
	crudClient crud.CrudClient[CrudProxy],
	proxyId string,
	fieldsToUpdate map[string]any,
) (*CrudProxy, error) {
	if err := validatePatchInput(fieldsToUpdate); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidPatchRequest, err)
	}

	if hasField(fieldsToUpdate, "targetBaseUrl") && fieldsToUpdate["targetBaseUrl"] != nil {
		targetBaseURL, ok := fieldsToUpdate["targetBaseUrl"].(string)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrInvalidPatchRequest, "targetBaseUrl is not a string")
		}

		if err := assertAllowedTargetBaseURL(ctx, targetBaseURL); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidPatchRequest, err)
		}
	}

	patchBody := generateCRUDPatchBody(fieldsToUpdate)

	return crudClient.PatchById(ctx, proxyId, patchBody, crud.Options{})
}

func UpdateProxyByBasePath(
	ctx context.Context,
	crudClient crud.CrudClient[CrudProxy],
	basePath string,
	fieldsToUpdate map[string]any,
) (int, error) {
	if basePath == "" {
		return 0, fmt.Errorf("basePath not specified")
	}

	if err := validatePatchInput(fieldsToUpdate); err != nil {
		return 0, fmt.Errorf("%w: %s", ErrInvalidPatchRequest, err)
	}

	if hasField(fieldsToUpdate, "targetBaseUrl") && fieldsToUpdate["targetBaseUrl"] != nil {
		targetBaseURL, ok := fieldsToUpdate["targetBaseUrl"].(string)
		if !ok {
			return 0, fmt.Errorf("%w: %s", ErrInvalidPatchRequest, "targetBaseUrl is not a string")
		}

		if err := assertAllowedTargetBaseURL(ctx, targetBaseURL); err != nil {
			return 0, fmt.Errorf("%w: %s", ErrInvalidPatchRequest, err)
		}
	}

	crudFilterOptions := crud.Options{
		Filter: buildBasePathFilter(basePath),
	}
	patchBody := generateCRUDPatchBody(fieldsToUpdate)

	return crudClient.PatchMany(ctx, patchBody, crudFilterOptions)
}

type FilterProxiesOptions struct {
	BasePath       *string
	BasePathList   []string
	BasePathPrefix *string
	Page           *int
	PerPage        *int
}

func GetProxies(
	ctx context.Context,
	crudClient crud.CrudClient[CrudProxy],
	options FilterProxiesOptions,
) ([]CrudProxy, error) {
	crudFilterOptions := crud.Options{
		Filter: buildCrudFilter(options),
	}

	proxies, err := crudClient.List(ctx, crudFilterOptions)
	if err != nil {
		return nil, err
	}

	return proxies, nil
}

func CountProxies(
	ctx context.Context,
	crudClient crud.CrudClient[CrudProxy],
	options FilterProxiesOptions,
) (int, error) {
	crudFilterOptions := crud.Options{
		Filter: buildCrudFilter(options),
	}

	count, err := crudClient.Count(ctx, crudFilterOptions)
	if err != nil {
		return 0, err
	}

	return count, nil
}

func DeleteProxyByBasePath(
	ctx context.Context,
	crudClient crud.CrudClient[CrudProxy],
	basePath string,
) (int, error) {
	if basePath == "" {
		return 0, fmt.Errorf("basePath not specified")
	}

	return deleteMany(ctx, crudClient, FilterProxiesOptions{
		BasePath: &basePath,
	})
}

func DeleteProxiesMatchingPrefix(
	ctx context.Context,
	crudClient crud.CrudClient[CrudProxy],
	basePathPrefix string,
) (int, error) {
	if basePathPrefix == "" {
		return 0, fmt.Errorf("basePathPrefix not specified")
	}

	return deleteMany(ctx, crudClient, FilterProxiesOptions{
		BasePathPrefix: &basePathPrefix,
	})
}

func deleteMany(
	ctx context.Context,
	crudClient crud.CrudClient[CrudProxy],
	filterOptions FilterProxiesOptions,
) (int, error) {
	crudFilterOptions := crud.Options{
		Filter: buildCrudFilter(filterOptions),
	}

	count, err := crudClient.DeleteMany(ctx, crudFilterOptions)
	if err != nil {
		return 0, err
	}

	return count, nil
}

func buildCrudFilter(filterOptions FilterProxiesOptions) crud.Filter {
	crudFilter := crud.Filter{}

	if filterOptions.BasePath != nil && *filterOptions.BasePath != "" {
		crudFilter = buildBasePathFilter(*filterOptions.BasePath)
	}

	if len(filterOptions.BasePathList) > 0 {
		crudFilter = buildBasePathInFilter(filterOptions.BasePathList)
	}

	if filterOptions.BasePathPrefix != nil && *filterOptions.BasePathPrefix != "" {
		crudFilter = buildBasePathPrefixFilter(*filterOptions.BasePathPrefix)
	}

	if filterOptions.Page != nil && filterOptions.PerPage != nil {
		crudFilter.Skip = (*filterOptions.Page - 1) * (*filterOptions.PerPage)
		crudFilter.Limit = *filterOptions.PerPage
	}

	return crudFilter
}

func buildBasePathFilter(basePath string) crud.Filter {
	return crud.Filter{
		MongoQuery: mongohelpers.MongoQuery{
			"basePath": basePath,
		},
	}
}

func buildBasePathInFilter(basePathList []string) crud.Filter {
	return crud.Filter{
		MongoQuery: map[string]any{
			"basePath": mongohelpers.MongoInFilter{
				In: basePathList,
			},
		},
	}
}

func buildBasePathPrefixFilter(basePathPrefix string) crud.Filter {
	prefixRegex := fmt.Sprintf(`^%s/`, basePathPrefix)

	return crud.Filter{
		MongoQuery: mongohelpers.MongoQuery{
			"basePath": mongohelpers.MongoRegex{
				Regex: prefixRegex,
			},
		},
	}
}
