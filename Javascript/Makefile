# https://lithic.tech/blog/2020-05/makefile-dot-env
include .env.example
export
DOCKER_ENV_FILE_PARAM = --env-file .env.example
ifneq (,$(wildcard ./.env))
	include .env
	export
	DOCKER_ENV_FILE_PARAM = --env-file .env.example --env-file .env
endif

.DEFAULT_GOAL := run

PRIVATE_KEY_FULL_FILE_NAME = $(shell readlink -f $(PRIVATE_KEY_FILE))

DOCKER ?= docker

HERE = $(shell pwd)
DOCKER_IMAGE_LOCAL_DEV ?= upvest-http-message-signing-in-js:latest

.PHONY: build
build:
	$(DOCKER) build \
		--file Dockerfile \
		--tag $(DOCKER_IMAGE_LOCAL_DEV) \
		.

.PHONY: run
run: build
	$(DOCKER) run \
		--rm \
		--tty \
		--interactive \
		$(DOCKER_ENV_FILE_PARAM) \
		--env PRIVATE_KEY_FILE=/work/private_key.pem \
		--volume $(PRIVATE_KEY_FULL_FILE_NAME):/work/private_key.pem \
		--volume $(HERE)/Canonicaliser.mjs:/work/Canonicaliser.mjs \
		--volume $(HERE)/NodeKeyLoader.mjs:/work/NodeKeyLoader.mjs \
		--volume $(HERE)/Signature.mjs:/work/Signature.mjs \
		--volume $(HERE)/UpvestNodeAxiosInterceptor.mjs:/work/UpvestNodeAxiosInterceptor.mjs \
		--volume $(HERE)/UpvestNodeSigner.mjs:/work/UpvestNodeSigner.mjs \
		--volume $(HERE)/example.mjs:/work/example.mjs \
		--volume $(HERE)/index.mjs:/work/index.mjs \
		--volume $(HERE)/settings.mjs:/work/settings.mjs \
		--volume $(HERE)/util.mjs:/work/util.mjs \
		--volume $(HERE)/package.json:/work/package.json \
		--volume $(HERE)/run.sh:/work/run.sh \
		--volume $(HERE)/node_modules:/work/node_modules \
		$(DOCKER_IMAGE_LOCAL_DEV)
