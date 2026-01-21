VERSION ?= latest
DOCKER_IMAGE_NAME ?= core/proxy-manager

# Image URL to use all building/pushing image targets
IMG ?= $(DOCKER_IMAGE_NAME):$(VERSION)

# Create a variable that contains the current date in UTC
# Different flow if this script is running on Darwin or Linux machines.
ifeq (Darwin,$(shell uname))
	NOW_DATE = $(shell date -u +%d-%m-%Y)
else
	NOW_DATE = $(shell date -u -I)
endif

all: test

.PHONY: local-start
local-start:
	set -a && source local.env && go run proxy-manager

.PHONY: test
test:
	go test ./... -coverprofile coverage.out

.PHONY: version
version:
	sed -i.bck "s|## Unreleased|## Unreleased\n\n## ${VERSION} - ${NOW_DATE}|g" "CHANGELOG.md"
	sed -i.bck "s|SERVICE_VERSION=\"[0-9]*.[0-9]*.[0-9]*.*\"|SERVICE_VERSION=\"${VERSION}\"|" "Dockerfile"
	rm -fr "CHANGELOG.md.bck" "Dockerfile.bck"
	git add "CHANGELOG.md" "Dockerfile"
	git commit -m "Upgrade version to v${VERSION}"
	git tag v${VERSION}

.PHONY: docker-build
docker-build: test ## Build docker image with the manager.
	docker build -t ${IMG} .
