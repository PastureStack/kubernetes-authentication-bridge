TARGETS := $(shell find scripts -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)
DAPPER_IMAGE ?= pasturestack-kubernetes-authentication-bridge-dapper:ubuntu26
DAPPER_SOURCE ?= /source
DAPPER_HOST_ARCH ?= amd64
DOCKER_VERSION ?= 29.7.2
DOCKER_BUILD_NETWORK ?= host

dapper-image:
	docker build \
		--network $(DOCKER_BUILD_NETWORK) \
		--build-arg DAPPER_HOST_ARCH=$(DAPPER_HOST_ARCH) \
		--build-arg DOCKER_VERSION=$(DOCKER_VERSION) \
		-t $(DAPPER_IMAGE) \
		-f Dockerfile.dapper .

$(TARGETS): dapper-image
	docker run --rm \
		-v $(CURDIR):$(DAPPER_SOURCE) \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-e DAPPER_UID=$$(id -u) \
		-e DAPPER_GID=$$(id -g) \
		-e ARCH=$(DAPPER_HOST_ARCH) \
		-e IMAGE_NAME \
		-e TAG \
		-e VERSION_OVERRIDE \
		-e SOURCE_REVISION \
		-e DOCKER_BUILD_NETWORK=$(DOCKER_BUILD_NETWORK) \
		$(DAPPER_IMAGE) $@

.DEFAULT_GOAL := ci

.PHONY: dapper-image $(TARGETS)
