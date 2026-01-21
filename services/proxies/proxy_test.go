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
	"fmt"
	"testing"

	"proxy-manager/internal/config"
	"proxy-manager/internal/mongohelpers"
	allowedtargets_repository "proxy-manager/repositories/allowedtargets"
	allowedtargets_service "proxy-manager/services/allowedtargets"

	"github.com/mia-platform/go-crud-service-client"
	"github.com/mia-platform/go-crud-service-client/testhelper/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testAuthMethod = "oauth2"
	testGrantType  = "password"
	testUsername   = "SomeUsername"
	testPassword   = "ThisShouldNotBeReturned"

	emptyString = ""
)

func TestCreateProxy(t *testing.T) {
	t.Run("error if target allowList defined and requested target is not allowed", func(t *testing.T) {
		proxyToCreate := CrudProxy{
			BasePath:      "/path1/path2",
			TargetBaseUrl: "https://some-host",
		}

		proxiesCrud := &mock.CRUD[CrudProxy]{
			CreateResult: "proxy_oid",
			CreateAssertionFunc: func(_ context.Context, resource CrudProxy, options crud.Options) {
				require.Equal(t, proxyToCreate, resource)
			},
		}

		repo, err := allowedtargets_repository.FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{"https://api.allowed-domain.com"},
		})
		require.Nil(t, err)

		ctx := allowedtargets_service.RegisterInstance(
			context.Background(),
			allowedtargets_service.New(repo),
		)

		_, err = CreateProxy(ctx, proxiesCrud, proxyToCreate)
		require.NotNil(t, err)
		require.EqualError(t, err, "specified target URL is not allowed")
	})

	t.Run("error creating proxy", func(t *testing.T) {
		proxyToCreate := CrudProxy{
			BasePath:      "/path1/path2",
			TargetBaseUrl: "https://some-host/",
		}

		proxiesCrud := &mock.CRUD[CrudProxy]{
			CreateError: fmt.Errorf("item creation failed"),
		}

		repo, err := allowedtargets_repository.FromENV(config.EnvironmentVariables{})
		require.Nil(t, err)

		ctx := allowedtargets_service.RegisterInstance(
			context.Background(),
			allowedtargets_service.New(repo),
		)

		_, err = CreateProxy(ctx, proxiesCrud, proxyToCreate)
		require.NotNil(t, err)
		require.EqualError(t, err, "item creation failed")
	})

	t.Run("success if target allowList defined and requested target is allowed", func(t *testing.T) {
		proxyToCreate := CrudProxy{
			BasePath:      "/path1/path2",
			TargetBaseUrl: "https://api.allowed-domain.com/path",
		}

		repo, err := allowedtargets_repository.FromENV(config.EnvironmentVariables{
			AllowedProxyTargetURLs: []string{"https://api.allowed-domain.com"},
		})

		ctx := allowedtargets_service.RegisterInstance(
			context.Background(),
			allowedtargets_service.New(repo),
		)

		proxiesCrud := &mock.CRUD[CrudProxy]{
			CreateResult: "proxy_oid",
			CreateAssertionFunc: func(_ context.Context, resource CrudProxy, options crud.Options) {
				require.Equal(t, proxyToCreate, resource)
			},
		}

		proxyId, err := CreateProxy(ctx, proxiesCrud, proxyToCreate)
		assert.Nil(t, err)
		assert.Equal(t, "proxy_oid", proxyId, "Crud was not called")
	})

	t.Run("successfully create proxy", func(t *testing.T) {
		proxyToCreate := CrudProxy{
			BasePath:      "/path1/path2",
			TargetBaseUrl: "https://some-host/",
		}

		proxiesCrud := &mock.CRUD[CrudProxy]{
			CreateResult: "proxy_oid",
			CreateAssertionFunc: func(_ context.Context, resource CrudProxy, options crud.Options) {
				require.Equal(t, proxyToCreate, resource)
			},
		}

		repo, err := allowedtargets_repository.FromENV(config.EnvironmentVariables{})
		require.Nil(t, err)

		ctx := allowedtargets_service.RegisterInstance(
			context.Background(),
			allowedtargets_service.New(repo),
		)

		proxyId, err := CreateProxy(ctx, proxiesCrud, proxyToCreate)
		assert.Nil(t, err)
		assert.Equal(t, "proxy_oid", proxyId, "Crud was not called")
	})
}

func TestUpdateProxyById(t *testing.T) {
	newBasePath := "/new-path"
	newTargetBaseUrl := "https://some-host/"

	repo, err := allowedtargets_repository.FromENV(config.EnvironmentVariables{})
	require.Nil(t, err)
	defaultContext := allowedtargets_service.RegisterInstance(
		context.Background(),
		allowedtargets_service.New(repo),
	)

	t.Run("error updating proxy", func(t *testing.T) {
		proxyId := "1234"
		proxyToUpdate := map[string]any{
			"basePath":      newBasePath,
			"targetBaseUrl": newTargetBaseUrl,
		}

		proxiesCrud := &mock.CRUD[CrudProxy]{
			PatchError: fmt.Errorf("item update failed"),
		}

		_, err = UpdateProxyById(defaultContext, proxiesCrud, proxyId, proxyToUpdate)
		require.NotNil(t, err)
		require.EqualError(t, err, "item update failed")
	})

	t.Run("error updating proxy with not allowed target", func(t *testing.T) {
		proxyId := "1234"
		proxyToUpdate := map[string]any{
			"basePath":      newBasePath,
			"targetBaseUrl": "https://invalid-host.com",
		}

		proxiesCrud := &mock.CRUD[CrudProxy]{
			PatchResult: &CrudProxy{},
			PatchAssertionFunc: func(ctx context.Context, id string, body crud.PatchBody, options crud.Options) {
				t.Error("should not be called")
			},
		}

		repo, err := allowedtargets_repository.FromENV(
			config.EnvironmentVariables{
				AllowedProxyTargetURLs: []string{
					"https://somehost.com",
				},
			},
		)
		require.Nil(t, err)

		ctx := allowedtargets_service.RegisterInstance(
			context.Background(),
			allowedtargets_service.New(repo),
		)

		_, err = UpdateProxyById(ctx, proxiesCrud, proxyId, proxyToUpdate)
		require.NotNil(t, err)
		require.EqualError(t, err, "invalid patch request: specified target URL is not allowed")
	})

	t.Run("successfully update proxy", func(t *testing.T) {
		fieldsToUpdate := map[string]any{
			"basePath":       newBasePath,
			"targetBaseUrl":  newTargetBaseUrl,
			"clientId":       "",
			"authentication": nil,
		}

		expectedProxy := &CrudProxy{
			BasePath:      "/new-path",
			TargetBaseUrl: "https://some-host/",
			ClientId:      &emptyString,
		}

		expectedPatchBody := crud.PatchBody{
			Set:   map[string]interface{}{"basePath": "/new-path", "targetBaseUrl": "https://some-host/", "clientId": ""},
			Unset: map[string]bool{"authentication": true},
		}

		proxiesCrud := &mock.CRUD[CrudProxy]{
			PatchResult: expectedProxy,
			PatchAssertionFunc: func(_ context.Context, id string, body crud.PatchBody, options crud.Options) {
				require.Equal(t, "1234", id)
				require.Equal(t, expectedPatchBody, body)
			},
		}

		updatedProxy, _ := UpdateProxyById(defaultContext, proxiesCrud, "1234", fieldsToUpdate)
		require.Equal(t, expectedProxy, updatedProxy, "Crud was not called")
	})

	t.Run("successfully update proxy with allowed target url", func(t *testing.T) {
		fieldsToUpdate := map[string]any{
			"basePath":       newBasePath,
			"targetBaseUrl":  newTargetBaseUrl,
			"clientId":       "",
			"authentication": nil,
		}

		expectedProxy := &CrudProxy{
			BasePath:      "/new-path",
			TargetBaseUrl: "https://some-host/api",
			ClientId:      &emptyString,
		}

		expectedPatchBody := crud.PatchBody{
			Set:   map[string]interface{}{"basePath": "/new-path", "targetBaseUrl": "https://some-host/", "clientId": ""},
			Unset: map[string]bool{"authentication": true},
		}

		proxiesCrud := &mock.CRUD[CrudProxy]{
			PatchResult: expectedProxy,
			PatchAssertionFunc: func(_ context.Context, id string, body crud.PatchBody, options crud.Options) {
				require.Equal(t, "1234", id)
				require.Equal(t, expectedPatchBody, body)
			},
		}

		repo, err := allowedtargets_repository.FromENV(
			config.EnvironmentVariables{
				AllowedProxyTargetURLs: []string{
					"https://some-host",
				},
			},
		)
		require.Nil(t, err)

		ctx := allowedtargets_service.RegisterInstance(
			context.Background(),
			allowedtargets_service.New(repo),
		)

		updatedProxy, _ := UpdateProxyById(ctx, proxiesCrud, "1234", fieldsToUpdate)
		require.Equal(t, expectedProxy, updatedProxy, "Crud was not called")
	})
}

func TestUpdateProxyByBasePath(t *testing.T) {
	newBasePath := "/new-path"
	newTargetBaseUrl := "https://some-host/"

	repo, err := allowedtargets_repository.FromENV(config.EnvironmentVariables{})
	require.Nil(t, err)
	defaultContext := allowedtargets_service.RegisterInstance(
		context.Background(),
		allowedtargets_service.New(repo),
	)

	t.Run("returns error when no basePath is speficied", func(t *testing.T) {
		crudClientMock := &mock.CRUD[CrudProxy]{}
		count, err := UpdateProxyByBasePath(defaultContext, crudClientMock, "", nil)

		assert.Equal(t, "basePath not specified", err.Error())
		assert.Equal(t, 0, count)
	})

	t.Run("returns error when some error occurs", func(t *testing.T) {
		errorFromCrud := "item update failed"
		crudClientMock := &mock.CRUD[CrudProxy]{
			PatchManyError: fmt.Errorf("%s", errorFromCrud),
		}

		count, err := UpdateProxyByBasePath(defaultContext, crudClientMock, "/base-path-to-update", nil)

		assert.Equal(t, errorFromCrud, err.Error())
		assert.Equal(t, 0, count)
	})

	t.Run("error updating proxy with not allowed target", func(t *testing.T) {
		proxyId := "1234"
		proxyToUpdate := map[string]any{
			"basePath":      newBasePath,
			"targetBaseUrl": "https://invalid-host.com",
		}

		expectedUpdateCount := 1
		proxiesCrud := &mock.CRUD[CrudProxy]{
			PatchManyResult: expectedUpdateCount,
			PatchManyAssertionFunc: func(ctx context.Context, body crud.PatchBody, options crud.Options) {
				t.Error("should not be called")
			},
		}

		repo, err := allowedtargets_repository.FromENV(
			config.EnvironmentVariables{
				AllowedProxyTargetURLs: []string{
					"https://somehost.com",
				},
			},
		)
		require.Nil(t, err)

		ctx := allowedtargets_service.RegisterInstance(
			context.Background(),
			allowedtargets_service.New(repo),
		)

		count, err := UpdateProxyByBasePath(ctx, proxiesCrud, proxyId, proxyToUpdate)

		require.EqualError(t, err, "invalid patch request: specified target URL is not allowed")
		assert.Equal(t, 0, count)
	})

	t.Run("returns updated proxies count correctly", func(t *testing.T) {
		expectedFilter := crud.Filter{
			MongoQuery: map[string]any{
				"basePath": "/base-path-to-update",
			},
		}

		fieldsToUpdate := map[string]any{
			"basePath":       newBasePath,
			"targetBaseUrl":  newTargetBaseUrl,
			"clientId":       "",
			"authentication": nil,
		}

		expectedPatchBody := crud.PatchBody{
			Set:   map[string]interface{}{"basePath": "/new-path", "targetBaseUrl": "https://some-host/", "clientId": ""},
			Unset: map[string]bool{"authentication": true},
		}

		expectedUpdateCount := 1
		crudClientMock := &mock.CRUD[CrudProxy]{
			PatchManyResult: expectedUpdateCount,
			PatchManyAssertionFunc: func(ctx context.Context, body crud.PatchBody, options crud.Options) {
				require.Equal(t, options.Filter, expectedFilter)
				require.Equal(t, expectedPatchBody, body)
			},
		}

		count, err := UpdateProxyByBasePath(defaultContext, crudClientMock, "/base-path-to-update", fieldsToUpdate)

		assert.Nil(t, err)
		assert.Equal(t, expectedUpdateCount, count)
	})

	t.Run("returns updated proxies count correctly with allowed target url", func(t *testing.T) {
		expectedFilter := crud.Filter{
			MongoQuery: map[string]any{
				"basePath": "/base-path-to-update",
			},
		}

		fieldsToUpdate := map[string]any{
			"basePath":       newBasePath,
			"targetBaseUrl":  newTargetBaseUrl,
			"clientId":       "",
			"authentication": nil,
		}

		expectedPatchBody := crud.PatchBody{
			Set:   map[string]interface{}{"basePath": "/new-path", "targetBaseUrl": "https://some-host/", "clientId": ""},
			Unset: map[string]bool{"authentication": true},
		}

		expectedUpdateCount := 1
		crudClientMock := &mock.CRUD[CrudProxy]{
			PatchManyResult: expectedUpdateCount,
			PatchManyAssertionFunc: func(ctx context.Context, body crud.PatchBody, options crud.Options) {
				require.Equal(t, options.Filter, expectedFilter)
				require.Equal(t, expectedPatchBody, body)
			},
		}

		repo, err := allowedtargets_repository.FromENV(
			config.EnvironmentVariables{
				AllowedProxyTargetURLs: []string{
					"https://some-host",
				},
			},
		)
		require.Nil(t, err)

		ctx := allowedtargets_service.RegisterInstance(
			context.Background(),
			allowedtargets_service.New(repo),
		)
		count, err := UpdateProxyByBasePath(ctx, crudClientMock, "/base-path-to-update", fieldsToUpdate)

		assert.Nil(t, err)
		assert.Equal(t, expectedUpdateCount, count)
	})
}

func TestGetProxies(t *testing.T) {
	t.Run("returns error when error occurs", func(t *testing.T) {
		errorFromCrud := "item retrieval failed"
		crudClientMock := &mock.CRUD[CrudProxy]{
			ListError: fmt.Errorf("%s", errorFromCrud),
		}

		testBasePath := ""
		proxies, err := GetProxies(context.Background(), crudClientMock, FilterProxiesOptions{
			BasePath: &testBasePath,
		})

		assert.Equal(t, "item retrieval failed", err.Error())
		assert.Nil(t, proxies)
	})

	t.Run("returns proxies correctly", func(t *testing.T) {
		expectedProxyList := []CrudProxy{
			{
				BasePath:       "/base-path-1",
				TargetBaseUrl:  "https://target.url/api/v1",
				Authentication: &testAuthMethod,
				GrantType:      &testGrantType,
				Username:       &testUsername,
				Password:       &testPassword,
			},
		}
		expectedFilter := crud.Filter{}
		crudClientMock := &mock.CRUD[CrudProxy]{
			ListResult: expectedProxyList,
			ListAssertionFunc: func(ctx context.Context, options crud.Options) {
				require.Equal(t, options.Filter, expectedFilter)
			},
		}

		testBasePath := ""
		proxies, err := GetProxies(context.Background(), crudClientMock, FilterProxiesOptions{
			BasePath: &testBasePath,
		})

		assert.Nil(t, err)
		require.Equal(t, expectedProxyList, proxies)
	})

	t.Run("returns proxies correctly with filter on basePath", func(t *testing.T) {
		testBasePath := "base-path-1"
		expectedProxyList := []CrudProxy{
			{
				BasePath:       "/base-path-1",
				TargetBaseUrl:  "https://target.url/api/v1",
				Authentication: &testAuthMethod,
				GrantType:      &testGrantType,
				Username:       &testUsername,
				Password:       &testPassword,
			},
			{
				BasePath:       "/base-path-2",
				TargetBaseUrl:  "https://target.url/api/v2",
				Authentication: &testAuthMethod,
				GrantType:      &testGrantType,
				ClientId:       &testUsername,
				ClientSecret:   &testPassword,
			},
		}
		expectedFilter := crud.Filter{
			MongoQuery: map[string]any{
				"basePath": testBasePath,
			},
		}
		crudClientMock := &mock.CRUD[CrudProxy]{
			ListResult: expectedProxyList,
			ListAssertionFunc: func(ctx context.Context, options crud.Options) {
				require.Equal(t, options.Filter, expectedFilter)
			},
		}

		proxies, err := GetProxies(context.Background(), crudClientMock, FilterProxiesOptions{
			BasePath: &testBasePath,
		})

		assert.Nil(t, err)
		require.Equal(t, expectedProxyList, proxies)
	})

	t.Run("returns proxies correctly with filter on pages", func(t *testing.T) {
		page := 3
		perPage := 2
		expectedProxyList := []CrudProxy{
			{
				BasePath:       "/base-path-1",
				TargetBaseUrl:  "https://target.url/api/v1",
				Authentication: &testAuthMethod,
				GrantType:      &testGrantType,
				Username:       &testUsername,
				Password:       &testPassword,
			},
			{
				BasePath:       "/base-path-2",
				TargetBaseUrl:  "https://target.url/api/v2",
				Authentication: &testAuthMethod,
				GrantType:      &testGrantType,
				ClientId:       &testUsername,
				ClientSecret:   &testPassword,
			},
		}
		expectedFilter := crud.Filter{
			Skip:  4,
			Limit: 2,
		}
		crudClientMock := &mock.CRUD[CrudProxy]{
			ListResult: expectedProxyList,
			ListAssertionFunc: func(ctx context.Context, options crud.Options) {
				require.Equal(t, options.Filter, expectedFilter)
			},
		}

		proxies, err := GetProxies(context.Background(), crudClientMock, FilterProxiesOptions{
			Page:    &page,
			PerPage: &perPage,
		})

		assert.Nil(t, err)
		require.Equal(t, expectedProxyList, proxies)
	})
}

func TestCountProxies(t *testing.T) {
	t.Run("error counting proxies", func(t *testing.T) {
		proxiesCrud := &mock.CRUD[CrudProxy]{
			CountError: fmt.Errorf("count failed"),
		}

		_, err := CountProxies(context.Background(), proxiesCrud, FilterProxiesOptions{})
		require.NotNil(t, err)
		require.EqualError(t, err, "count failed")
	})

	t.Run("successfully count proxies", func(t *testing.T) {
		basePath := "/base-path-1"
		expectedFilter := crud.Filter{
			MongoQuery: map[string]any{
				"basePath": basePath,
			},
		}

		proxiesCrud := &mock.CRUD[CrudProxy]{
			CountResult: 6,
			CountAssertionFunc: func(ctx context.Context, options crud.Options) {
				require.Equal(t, expectedFilter, options.Filter)
			},
		}

		count, _ := CountProxies(context.Background(), proxiesCrud, FilterProxiesOptions{
			BasePath: &basePath,
		})
		assert.Equal(t, count, 6, "Crud was not called")
	})
}

func TestDeleteProxyByBasePath(t *testing.T) {
	t.Run("returns error when no basePath is speficied", func(t *testing.T) {
		crudClientMock := &mock.CRUD[CrudProxy]{}
		count, err := DeleteProxyByBasePath(context.Background(), crudClientMock, "")

		assert.Equal(t, "basePath not specified", err.Error())
		assert.Equal(t, 0, count)
	})

	t.Run("returns error when some error occurs", func(t *testing.T) {
		errorFromCrud := "item deletion failed"
		crudClientMock := &mock.CRUD[CrudProxy]{
			DeleteManyError: fmt.Errorf("%s", errorFromCrud),
		}

		count, err := DeleteProxyByBasePath(context.Background(), crudClientMock, "/base-path-to-delete")

		assert.Equal(t, "item deletion failed", err.Error())
		assert.Equal(t, 0, count)
	})

	t.Run("returns deleted proxies count correctly", func(t *testing.T) {
		expectedFilter := crud.Filter{
			MongoQuery: map[string]any{
				"basePath": "/base-path-to-delete",
			},
		}
		expectedDeleteCount := 1
		crudClientMock := &mock.CRUD[CrudProxy]{
			DeleteManyResult: expectedDeleteCount,
			DeleteManyAssertionFunc: func(ctx context.Context, options crud.Options) {
				require.Equal(t, options.Filter, expectedFilter)
			},
		}

		count, err := DeleteProxyByBasePath(context.Background(), crudClientMock, "/base-path-to-delete")

		assert.Nil(t, err)
		assert.Equal(t, expectedDeleteCount, count)
	})
}

func TestDeleteProxiesMatchingPrefix(t *testing.T) {
	t.Run("returns error when no basePathPrefix is speficied", func(t *testing.T) {
		crudClientMock := &mock.CRUD[CrudProxy]{}
		count, err := DeleteProxiesMatchingPrefix(context.Background(), crudClientMock, "")

		assert.Equal(t, "basePathPrefix not specified", err.Error())
		assert.Equal(t, 0, count)
	})

	t.Run("returns error when some error occurs", func(t *testing.T) {
		errorFromCrud := "item deletion failed"
		crudClientMock := &mock.CRUD[CrudProxy]{
			DeleteManyError: fmt.Errorf("%s", errorFromCrud),
		}

		count, err := DeleteProxiesMatchingPrefix(context.Background(), crudClientMock, "/common-prefix")

		assert.Equal(t, "item deletion failed", err.Error())
		assert.Equal(t, 0, count)
	})

	t.Run("returns deleted proxies count correctly", func(t *testing.T) {
		expectedFilter := crud.Filter{
			MongoQuery: mongohelpers.MongoQuery{
				"basePath": mongohelpers.MongoRegex{Regex: "^/common-prefix/"},
			},
		}
		expectedDeleteCount := 1
		crudClientMock := &mock.CRUD[CrudProxy]{
			DeleteManyResult: expectedDeleteCount,
			DeleteManyAssertionFunc: func(ctx context.Context, options crud.Options) {
				require.Equal(t, options.Filter, expectedFilter)
			},
		}

		count, err := DeleteProxiesMatchingPrefix(context.Background(), crudClientMock, "/common-prefix")

		assert.Nil(t, err)
		assert.Equal(t, expectedDeleteCount, count)
	})
}

func TestValidatePatchInput(t *testing.T) {
	testCases := []struct {
		name     string
		input    map[string]any
		expected error
	}{
		{
			name: "all fine",
			input: map[string]any{
				"targetBaseUrl": "some-thing",
			},
			expected: nil,
		},
		{
			name: "invalid authentication value",
			input: map[string]any{
				"authentication": "guesswhat",
			},
			expected: ErrPatchInputInvalidAuthentication,
		},
		{
			name: "ok with authentication=none",
			input: map[string]any{
				"authentication": AuthenticationModeNone,
			},
			expected: nil,
		},
		{
			name: "fail with authentication=oauth2 but no grant type specified",
			input: map[string]any{
				"authentication": AuthenticationModeOauth2,
			},
			expected: ErrPatchInputMissingGrantTypeForOauth2,
		},
		{
			name: "fail with authentication=none but has grant type specified",
			input: map[string]any{
				"authentication": AuthenticationModeNone,
				"grantType":      "something",
			},
			expected: ErrPatchInputAuthNoneWithCredentials,
		},
		{
			name: "fail with authentication=none but has username specified",
			input: map[string]any{
				"authentication": AuthenticationModeNone,
				"username":       "something",
			},
			expected: ErrPatchInputAuthNoneWithCredentials,
		},
		{
			name: "fail with authentication=none but has password specified",
			input: map[string]any{
				"authentication": AuthenticationModeNone,
				"password":       "something",
			},
			expected: ErrPatchInputAuthNoneWithCredentials,
		},
		{
			name: "fail with authentication=none but has clientId specified",
			input: map[string]any{
				"authentication": AuthenticationModeNone,
				"clientId":       "something",
			},
			expected: ErrPatchInputAuthNoneWithCredentials,
		},
		{
			name: "fail with authentication=none but has clientSecret specified",
			input: map[string]any{
				"authentication": AuthenticationModeNone,
				"clientSecret":   "something",
			},
			expected: ErrPatchInputAuthNoneWithCredentials,
		},
		{
			name: "fail with authentication=none but has authType specified",
			input: map[string]any{
				"authentication": AuthenticationModeNone,
				"authType":       "something",
			},
			expected: ErrPatchInputAuthNoneWithCredentials,
		},
		{
			name: "fail with authentication=none but has tokenIssuerUrl specified",
			input: map[string]any{
				"authentication": AuthenticationModeNone,
				"tokenIssuerUrl": "something",
			},
			expected: ErrPatchInputAuthNoneWithCredentials,
		},
		{
			name: "fail with authentication=none but has tokenIssuerValidationUrl specified",
			input: map[string]any{
				"authentication":           AuthenticationModeNone,
				"tokenIssuerValidationUrl": "something",
			},
			expected: ErrPatchInputAuthNoneWithCredentials,
		},
		{
			name: "fail when patching gramt_type=password without providing proper credentials",
			input: map[string]any{
				"grantType": GrantTypePassword,
			},
			expected: ErrPatchInputMissingPasswordCredentials,
		},
		{
			name: "ok when patching gramt_type=password with proper credentials",
			input: map[string]any{
				"grantType": GrantTypePassword,
				"username":  "user",
				"password":  "pass",
			},
			expected: nil,
		},
		{
			name: "fail when patching gramt_type=client_credentials without providing proper credentials",
			input: map[string]any{
				"grantType": GrantTypeClientCredentials,
			},
			expected: ErrPatchInputMissingClientCredentials,
		},
		{
			name: "fail with invalid authType",
			input: map[string]any{
				"authType": "some-invalid-auth-type",
			},
			expected: ErrPatchInputInvalidAuthType,
		},
		{
			name: "ok with valid authType",
			input: map[string]any{
				"authType": ClientCredentialsAuthTypeBasic,
			},
			expected: nil,
		},
		{
			name: "ok when patching gramt_type=client_credentials with proper credentials",
			input: map[string]any{
				"grantType":    GrantTypeClientCredentials,
				"clientId":     "user",
				"clientSecret": "pass",
			},
			expected: nil,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("test case #%d - %s", i+1, testCase.name), func(t *testing.T) {
			require.Equal(t, testCase.expected, validatePatchInput(testCase.input))
		})
	}

}

func TestGenerateCRUDPatchBOdy(t *testing.T) {
	testCases := []struct {
		name     string
		input    map[string]any
		expected crud.PatchBody
	}{
		{
			name: "random field names",
			input: map[string]any{
				"field1":  "hello",
				"field2":  42,
				"toUnset": nil,
			},
			expected: crud.PatchBody{
				Set: map[string]any{
					"field1": "hello",
					"field2": 42,
				},
				Unset: map[string]bool{
					"toUnset": true,
				},
			},
		},
		{
			name: "forcibly unsets all authn-based properties if authentication=none",
			input: map[string]any{
				"authentication": AuthenticationModeNone,
			},
			expected: crud.PatchBody{
				Set: map[string]any{
					"authentication": AuthenticationModeNone,
				},
				Unset: map[string]bool{
					"username":                 true,
					"password":                 true,
					"clientId":                 true,
					"clientSecret":             true,
					"tokenIssuerUrl":           true,
					"tokenIssuerValidationUrl": true,
					"grantType":                true,
					"authType":                 true,
				},
			},
		},
		{
			name: "forcibly unsets client credentials fields if auth is set to password",
			input: map[string]any{
				"grantType": GrantTypePassword,
			},
			expected: crud.PatchBody{
				Set: map[string]any{
					"grantType": GrantTypePassword,
				},
				Unset: map[string]bool{
					"clientId":     true,
					"clientSecret": true,
					"authType":     true,
				},
			},
		},
		{
			name: "forcibly unsets password fields if auth is set to client-credentials",
			input: map[string]any{
				"grantType": GrantTypeClientCredentials,
			},
			expected: crud.PatchBody{
				Set: map[string]any{
					"grantType": GrantTypeClientCredentials,
				},
				Unset: map[string]bool{
					"username": true,
					"password": true,
				},
			},
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("test case #%d - %s", i+1, testCase.name), func(t *testing.T) {
			require.Equal(t, testCase.expected, generateCRUDPatchBody(testCase.input))
		})
	}
}
