# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 3.6.0 - 30-07-2025

### Added

- added `TOKEN_PREEMPTIVE_EXPIRY_SECONDS` environment variable to configure preemptive token expiry buffer, preventing race conditions between token validation and usage (default: 30 seconds)

### Fixed

- fixed OAuth2 token race conditions that could cause 401 errors when tokens expire between validation check and actual request

## 3.5.0 - 2025-01-23

### Fixed

- exposed management routes under `SERVICE_PREFIX`

### Added

- added `DISALLOWED_RESPONSE_CONTENT_TYPE_LIST` env to prevent specified `Content-Type` headers in the response of the target service.
- added `ALLOWED_PROXY_TARGET_URLS` env to specify which target URLs are allowed as targetBaseUrl for a proxy.

## 3.4.4 - 13-01-2025

### Updated

- `GET /-/proxies` management API supports filtering for multiple `basePath`. This can be either a string or a comma-separated list of strings

## 3.4.3 - 2024-12-18

### Fixed

- fixed optimized mode that was ignored on `"authentication": "none"`
- ensuring not following redirect on optimized mode

## 3.4.2 - 2024-12-16

### Fixed

- patch api failure if proxy authentication is set to invalid value
- return `tokenIssuerUrl` and `tokenIssuerValidationUrl` from GET management API

## 3.4.1 - 11-12-2024

### Updated

- better patch request payload validation

## 3.4.0 - 09-12-2024

### Added

- added `HEADERS_TO_REMAP` env to remap specified headers into other specified header key.
- added `HEADER_BLOCK_LIST` env to prevent specified headers from being forwarded to the target URL.
- ci: sbom generation

## 3.3.3 - 2024-12-02

- internal context management for crud dependency

## 3.3.2 - 29-11-2024

### Fixed

- fixed API responses preventing empty strings to be returned if fields are missing

## 3.3.1 - 27-11-2024

### Fixed

- `DISABLE_PROXY_CACHE`: correctly prevents cache to be written when disabled

## 3.3.0 - 22-11-2024

### Added

- `BASE_PATH_MATCHERS`: to make it possible to fetch complex base paths when using dynamic configuration rather than taking the first segment only.
- `DISABLE_PROXY_CACHE`: to make it possible to disable the in-memory proxy cache when using dynamic configuration.

## 3.2.0 - 15-11-2024

### Added

- Added GET `/-/proxies` API
- Added POST `/-/proxies` API
- Added DELETE `/-/proxies` API
- Added PATCH `/-/proxies/:proxyId` API
- Added PATCH `/-/proxies` API

### Refactor

- internal component refactor and improved standard library usage

### Fixed

- sanitize target base url trailing slash to prevent `//` token in final path

## 3.1.0 - 2024-10-29

### Added

- `ADDITIONAL_HEADERS_TO_REDACT` environment variable to set additional headers to redact in logs

### Security

- Redacted sensitive headers in logs

## 3.0.0 - 2023-09-14

### BREAKING CHANGES

- remove trailing slash to handle requests without path parameters. Using the following configuration and calling the path `/docs` the proxy-manager will call `https://docs.mia-platform.eu/docs` and no more `https://docs.mia-platform.eu/docs/`: 
```javascript
{
  "targetBaseUrl": "https://docs.mia-platform.eu/docs",
  "basePath": "/docs"
}
```

### Added

- add request body log


## 2.0.0 - 2023-05-24

### BREAKING CHANGES

- `SERVICE_PREFIX` must match the following regex `^/[a-zA-Z0-9_-]+$`
- remove entire `basePath` from request path and not only the first segment. Using the following configuration and calling the path `/mia/docs/fast-data` the proxy-manager will call `https://docs.mia-platform.eu/fast-data` and no more `https://docs.mia-platform.eu/docs/fast-data`:
```javascript
{
  "targetBaseUrl": "https://docs.mia-platform.eu/",
  "basePath": "/mia/docs"
}
```

## 1.6.2 - 2023-05-23

### Fixed

- remove configuration `targetBaseUrl` wrong update

## 1.6.1 - 2023-05-19

### Fixed

- `retrieveUrl` correctly interpolates path parameters in case of `SERVICE_PREFIX`

## 1.6.0 - 2023-05-18

### Added

- add `additionalHeaders` to configuration to handle headers that will be proxied to target url

### Changed

- `targetBaseUrl` and `basePath` can contain path parameters

## 1.5.1 - 29-09-2022

### Changed

- update AccessToken.ExpiresIn type from int to json.RawMessage

## 1.5.0 - 1/09/2022

### Added

- Support to [dynamic configuration](https://git.tools.mia-platform.eu/platform/core/proxy-manager/-/issues/4): proxies are fetched from a CRUD collection 

## 1.4.1 - 31-07-2022

### Fixed

- [JMRBA](https://makeitapp.atlassian.net/browse/JMRBA-139): the service now is able to proxy the query parameters

### Changed

- delete token from cache when response returns an HTTP 403 error

## 1.4.0 - 29-04-2022

### Added

- logic to refresh a token if its ExpiresAt date is set and the ExpiresAt date is earlier than current moment

### Fixed

- added a _modify response_ logic to reverse proxy, so that when an HTTP 401 error is encountered
 cached access token is removed. This allow to clean up token cache upon token expiration
 when parameter `TokenIssuerValidationUrl` is not set

### Changed

- updated service dependencies

## 1.3.0 - 25-11-2021

### Changed

- debug logs added to improve the troubleshooting experience
- [RJMR-36](https://makeitapp.atlassian.net/browse/RJMR-36): the service now support optimized proxy without saving request body in memory, this feature is controlled by `ALLOW_PROXY_OPTIMIZER` environment variables and does not perform any retry upon request failures
- [JMRBA-84](https://makeitapp.atlassian.net/browse/JMRBA-84): fix proxy manager optimized with rewrite req host and x-forwarded-for header

## 1.2.0 - 18-10-2021

### Added

- introduced a mechanism that allows, for each proxy config, to select whether all the headers
  or only a subset of them should be forwarded to the corresponding external service

## 1.1.0 - 11-05-2021

### Added

- introduced the support for the legacy grant type [`password`](https://oauth.net/2/grant-types/password/)
- introduced support to custom auth fields, so that it is possible
  to provide additional body fields in the token

### Changed

- improved how url-encoded forms are created

### Fixed

- added return keyword to proxy handler function to prevent continuing the execution
  when an unexpected status code is encountered
- restored original request body after reading it to prevent error in the case of
  token expiration

## 1.0.1 - 09-04-2021

- Docker image name changed to core/proxy-manager

## 1.0.0 - 08-03-2021

### Added

- First implementation featuring the following capabilities:
  - `client_credentials` grant type with the `client_secret_basic` authentication method.
  - `http` and `https` protocol schemes for target URL

